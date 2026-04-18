package rmi

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestStreamParsesRealCaptures runs FromStream against every real rmiregistry
// client→server capture. Because FromStream reads exactly each message's
// bytes (no sentinel peek at end-of-Call), feeding the exact .bin payload
// via bytes.NewReader is the key regression: if the streaming Call reader
// ever over-reads, it would hit io.ErrUnexpectedEOF mid-frame and fail
// here.
func TestStreamParsesRealCaptures(t *testing.T) {
	cases := []struct {
		op       string
		argCount int
	}{
		{"lookup", 1},
		{"list", 0},
		{"bind", 2},
		{"rebind", 2},
		{"unbind", 1},
	}
	for _, jdk := range fixtureJDKs {
		for _, tc := range cases {
			jdk, tc := jdk, tc
			t.Run(jdk+"/"+tc.op, func(t *testing.T) {
				data := loadRMIFixture(t, jdk, tc.op+"-c2s.bin")
				tr, err := FromStream(bytes.NewReader(data))
				require.NoError(t, err)
				require.NotNil(t, tr.Handshake)
				require.NotNil(t, tr.ClientEndpoint)
				require.Len(t, tr.Messages, 1)
				call, ok := tr.Messages[0].(*CallMessage)
				require.True(t, ok)
				require.True(t, call.ObjID.IsRegistry())
				require.Equal(t, RegistryInterfaceHash, call.MethodHash)
				require.Len(t, call.ObjectArgs, tc.argCount)
				require.NotNil(t, call.Decoded)
			})
		}
	}
}

// TestStreamHandshakeOnly: a stream that ends after the handshake + endpoint
// echo (no messages yet) must return cleanly. Covers the "caller closed the
// connection between frames" path.
func TestStreamHandshakeOnly(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(buildHandshake())
	buf.Write(buildClientEndpointEcho("myhost", 4444))

	tr, err := FromStream(&buf)
	require.NoError(t, err)
	require.NotNil(t, tr.Handshake)
	require.NotNil(t, tr.ClientEndpoint)
	require.Empty(t, tr.Messages)
}

// TestStreamRejectsNonRegistryCall: the ObjID is non-zero (not Registry),
// so we can't know the method's arg count without external schema. The
// streaming parser must error out instead of guessing.
func TestStreamRejectsNonRegistryCall(t *testing.T) {
	nonReg := ObjID{ObjNum: 99, UID: UID{Unique: 1, Time: 2, Count: 3}}
	data := buildCall(nonReg, LookupOpIndex, RegistryInterfaceHash, buildTCString("x"))

	_, err := FromStream(bytes.NewReader(data))
	require.Error(t, err)
	require.Contains(t, err.Error(), "only supports Registry")
}

// TestStreamRejectsWrongInterfaceHash: even with Registry ObjID, a
// mismatched interface hash means this isn't actually a Registry call.
// Streaming must refuse.
func TestStreamRejectsWrongInterfaceHash(t *testing.T) {
	const bogus int64 = 0x1234567890ABCDEF
	data := buildCall(ObjID{}, LookupOpIndex, bogus, buildTCString("x"))

	_, err := FromStream(bytes.NewReader(data))
	require.Error(t, err)
	require.Contains(t, err.Error(), "only supports Registry")
}

// TestStreamRejectsUnknownRegistryOp: Registry ObjID + correct hash but an
// op-index outside [0..4]. Without a known arg count we refuse to guess.
func TestStreamRejectsUnknownRegistryOp(t *testing.T) {
	data := buildCall(ObjID{}, 99, RegistryInterfaceHash, buildTCString("x"))

	_, err := FromStream(bytes.NewReader(data))
	require.Error(t, err)
	require.Contains(t, err.Error(), "known Registry op-indices")
}

// TestStreamRejectsReturn: NormalReturn's 0-vs-1 payload depends on the
// originating Call's return type; we have no way to know in a
// direction-agnostic stream. Error explicitly rather than guess wrong.
func TestStreamRejectsReturn(t *testing.T) {
	data := buildReturn(NormalReturn, UID{Unique: 1, Time: 2, Count: 3}, nil)

	_, err := FromStream(bytes.NewReader(data))
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not support ReturnData")
	require.Contains(t, err.Error(), "FromBytes")
}

// TestStreamPingPingAckDgcAck: bounded-length frames the streaming parser
// always handles. Tests that after one Call completes, we correctly return
// to the top-level loop and dispatch subsequent light-weight frames.
func TestStreamPingPingAckDgcAck(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(buildHandshake())
	buf.Write(buildClientEndpointEcho("h", 1))
	buf.Write(buildCall(ObjID{}, LookupOpIndex, RegistryInterfaceHash, buildTCString("a")))
	buf.Write(buildPing())
	buf.Write(buildDgcAck(UID{Unique: 7, Time: 8, Count: 9}))

	tr, err := FromStream(&buf)
	require.NoError(t, err)
	require.Len(t, tr.Messages, 3)
	require.Equal(t, MsgCall, tr.Messages[0].Op())
	require.Equal(t, MsgPing, tr.Messages[1].Op())
	require.Equal(t, MsgDgcAck, tr.Messages[2].Op())
}

// TestStreamExactReadNoSentinelLeak: prove that after the last arg of a
// Registry Call, the parser does NOT read one more byte trying to decide
// "is there another TCContent?". If it did, concatenating a second Call
// right after the first without any separator would break — but with exact
// reading, the two Calls should both parse cleanly.
func TestStreamExactReadNoSentinelLeak(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(buildHandshake())
	buf.Write(buildClientEndpointEcho("h", 1))
	// Two back-to-back Registry Calls with no intervening bytes.
	buf.Write(buildCall(ObjID{}, LookupOpIndex, RegistryInterfaceHash, buildTCString("first")))
	buf.Write(buildCall(ObjID{}, UnbindOpIndex, RegistryInterfaceHash, buildTCString("second")))

	tr, err := FromStream(&buf)
	require.NoError(t, err)
	require.Len(t, tr.Messages, 2)
	first := tr.Messages[0].(*CallMessage)
	second := tr.Messages[1].(*CallMessage)
	require.Equal(t, "Registry.lookup", first.Decoded.Method)
	require.Equal(t, "first", first.Decoded.Args[0].Value)
	require.Equal(t, "Registry.unbind", second.Decoded.Method)
	require.Equal(t, "second", second.Decoded.Args[0].Value)
}

// TestStreamIoPipeDelivery uses io.Pipe to simulate real network delivery
// where bytes arrive in chunks across time. Proves the streaming parser
// correctly handles partial reads across message boundaries. A timeout
// guards against the parser accidentally blocking past EOF.
func TestStreamIoPipeDelivery(t *testing.T) {
	data := loadRMIFixture(t, "jdk17", "lookup-c2s.bin")
	pr, pw := io.Pipe()

	go func() {
		defer func() { _ = pw.Close() }()
		// Write the bytes in small chunks with tiny delays to mimic TCP
		// segmentation. Each chunk triggers a separate Read on the parser side.
		for i := 0; i < len(data); i += 7 {
			end := i + 7
			if end > len(data) {
				end = len(data)
			}
			_, _ = pw.Write(data[i:end])
			time.Sleep(1 * time.Millisecond)
		}
	}()

	done := make(chan struct{})
	var tr *Transmission
	var err error
	go func() {
		tr, err = FromStream(pr)
		close(done)
	}()

	select {
	case <-done:
		require.NoError(t, err)
		require.NotNil(t, tr.Handshake)
		require.Len(t, tr.Messages, 1)
	case <-time.After(5 * time.Second):
		t.Fatal("FromStream did not return within 5s — likely blocked reading past end of stream")
	}
}
