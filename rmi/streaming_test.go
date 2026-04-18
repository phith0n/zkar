package rmi

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestStreamParsesRealCaptures runs FromStream against every real rmiregistry
// client→server capture. Registry Calls use the exact-count fast path, so
// feeding the exact .bin payload via bytes.NewReader — no trailing bytes —
// must parse cleanly without the parser over-reading and hitting
// io.ErrUnexpectedEOF mid-frame.
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

// Non-Registry Call rejection is covered by TestCallRejectsNonRegistry in
// rmi_test.go; the same readCall implementation backs both FromBytes and
// FromStream, so there's no separate streaming-side rejection test.

// TestStreamReturnWithPayload: ReturnData streaming via sentinel. A
// NormalReturn with one payload TCContent parses, payload count is 1.
func TestStreamReturnWithPayload(t *testing.T) {
	uid := UID{Unique: 1, Time: 2, Count: 3}
	data := buildReturn(NormalReturn, uid, buildTCString("result"))

	tr, err := FromStream(bytes.NewReader(data))
	require.NoError(t, err)
	require.Len(t, tr.Messages, 1)
	ret, ok := tr.Messages[0].(*ReturnMessage)
	require.True(t, ok)
	require.Equal(t, NormalReturn, ret.ReturnType)
	require.NotNil(t, ret.Payload)
}

// TestStreamReturnVoid: a ReturnData with no payload (void method) — the
// sentinel reads zero payload TCContents and terminates on io.EOF.
func TestStreamReturnVoid(t *testing.T) {
	uid := UID{Unique: 1, Time: 2, Count: 3}
	data := buildReturn(NormalReturn, uid, nil)

	tr, err := FromStream(bytes.NewReader(data))
	require.NoError(t, err)
	require.Len(t, tr.Messages, 1)
	ret := tr.Messages[0].(*ReturnMessage)
	require.Equal(t, NormalReturn, ret.ReturnType)
	require.Nil(t, ret.Payload)
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
