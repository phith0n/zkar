package rmi

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestDecoderFrameByFrame: Decoder yields one Message per Next() call,
// reports io.EOF at the end, and preserves the ordering of a handshake +
// Call + Ping + DgcAck sequence.
func TestDecoderFrameByFrame(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(buildHandshake())
	buf.Write(buildClientEndpointEcho("h", 1))
	buf.Write(buildCall(ObjID{}, LookupOpIndex, RegistryInterfaceHash, buildTCString("svc")))
	buf.Write(buildPing())
	buf.Write(buildDgcAck(UID{Unique: 7, Time: 8, Count: 9}))

	d := NewDecoder(&buf)

	opening, err := d.Opening()
	require.NoError(t, err)
	require.NotNil(t, opening.Handshake)
	require.NotNil(t, opening.ClientEndpoint)
	require.Nil(t, opening.Acknowledge)

	m1, err := d.Next()
	require.NoError(t, err)
	require.Equal(t, MsgCall, m1.Op())
	call := m1.(*CallMessage)
	require.Equal(t, "Registry.lookup", call.Decoded.Method)
	require.Equal(t, "svc", call.Decoded.Args[0].Value)

	m2, err := d.Next()
	require.NoError(t, err)
	require.Equal(t, MsgPing, m2.Op())

	m3, err := d.Next()
	require.NoError(t, err)
	require.Equal(t, MsgDgcAck, m3.Op())

	_, err = d.Next()
	require.True(t, errors.Is(err, io.EOF))
}

// TestDecoderSkipsOpeningWhenOmitted: calling Next() without first calling
// Opening() should transparently consume and discard any handshake prefix.
func TestDecoderSkipsOpeningWhenOmitted(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(buildHandshake())
	buf.Write(buildClientEndpointEcho("h", 1))
	buf.Write(buildPing())

	d := NewDecoder(&buf)
	msg, err := d.Next()
	require.NoError(t, err)
	require.Equal(t, MsgPing, msg.Op())
}

// TestDecoderOpeningTwiceErrors: Opening() is a once-only operation.
func TestDecoderOpeningTwiceErrors(t *testing.T) {
	d := NewDecoder(bytes.NewReader(buildHandshake()))
	_, err := d.Opening()
	require.NoError(t, err)
	_, err = d.Opening()
	require.Error(t, err)
}

// TestDecoderOpeningAfterNextErrors: once Next() has been called, Opening()
// may no longer be called.
func TestDecoderOpeningAfterNextErrors(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(buildPing())
	d := NewDecoder(&buf)
	_, err := d.Next()
	require.NoError(t, err)
	_, err = d.Opening()
	require.Error(t, err)
}

// TestDecoderBareCaptureNoOpening: a capture that starts mid-stream (no
// handshake, no ack) must work — Opening() returns a zero-value Opening
// and consumes nothing.
func TestDecoderBareCaptureNoOpening(t *testing.T) {
	d := NewDecoder(bytes.NewReader(buildPing()))
	opening, err := d.Opening()
	require.NoError(t, err)
	require.Nil(t, opening.Handshake)
	require.Nil(t, opening.Acknowledge)
	require.Nil(t, opening.ClientEndpoint)

	msg, err := d.Next()
	require.NoError(t, err)
	require.Equal(t, MsgPing, msg.Op())
}

// TestDecoderRegistryCallReturnsWithoutPeek: the Registry fast path reads
// exactly N args, so Decoder returns the frame as soon as the frame's own
// bytes arrive — we don't wait for any byte of a (nonexistent) next frame.
// Using io.Pipe with no Close after the final byte proves this: if the
// Decoder tried to peek ahead, the test would deadlock.
func TestDecoderRegistryCallReturnsWithoutPeek(t *testing.T) {
	data := loadRMIFixture(t, "jdk17", "lookup-c2s.bin")
	pr, pw := io.Pipe()

	// Writer feeds the exact Call bytes and then sits idle — it never closes
	// and never writes a next frame. If the parser peeks past the last arg,
	// the test deadlocks and the 2s timeout fires.
	go func() {
		_, _ = pw.Write(data)
		// Intentional: no Close. Simulates a live client that sent one Call
		// and is now waiting for the server's response.
	}()

	type result struct {
		msg Message
		err error
	}
	done := make(chan result, 1)
	go func() {
		d := NewDecoder(pr)
		_, openingErr := d.Opening()
		if openingErr != nil {
			done <- result{nil, openingErr}
			return
		}
		m, e := d.Next()
		done <- result{m, e}
	}()

	select {
	case r := <-done:
		require.NoError(t, r.err)
		require.Equal(t, MsgCall, r.msg.Op())
	case <-time.After(2 * time.Second):
		// Close the pipe so the goroutine can exit after we fail.
		_ = pw.CloseWithError(io.EOF)
		t.Fatal("Decoder.Next blocked past the last byte of a Registry Call — the exact-count fast path should have returned without peeking")
	}
}

// TestDecoderNonRegistryCallBlocksOnSentinelPeek: for a non-Registry Call
// we fall back to the sentinel, which peeks the byte after the last arg.
// On a live reader with no follow-up bytes, that peek blocks — documenting
// the Decoder's contract: callers must close the reader, send the next
// frame, or set a deadline to unblock.
//
// The test asserts both halves: (a) a short timeout fires while blocked,
// confirming the parser *is* waiting; (b) closing the writer end with
// io.EOF afterwards lets the parser return successfully, confirming the
// block is a peek-wait and not a bug.
func TestDecoderNonRegistryCallBlocksOnSentinelPeek(t *testing.T) {
	nonReg := ObjID{ObjNum: 42, UID: UID{Unique: 1, Time: 2, Count: 3}}
	data := buildCall(nonReg, LookupOpIndex, RegistryInterfaceHash, buildTCString("x"))
	pr, pw := io.Pipe()

	go func() {
		_, _ = pw.Write(data)
		// Keep writer open: mimics a live connection where the peer has sent
		// one Call and is waiting. The Decoder's sentinel peek has nothing
		// to read and must block.
	}()

	type result struct {
		msg Message
		err error
	}
	done := make(chan result, 1)
	go func() {
		d := NewDecoder(pr)
		m, e := d.Next()
		done <- result{m, e}
	}()

	// (a) Confirm it blocks while the pipe is open.
	select {
	case r := <-done:
		t.Fatalf("Decoder.Next returned before the pipe was closed (msg=%v err=%v) — non-Registry Call should block on sentinel peek", r.msg, r.err)
	case <-time.After(150 * time.Millisecond):
		// Expected: still blocked.
	}

	// (b) Close the writer → sentinel peek gets io.EOF → Decoder returns.
	require.NoError(t, pw.Close())

	select {
	case r := <-done:
		require.NoError(t, r.err)
		require.Equal(t, MsgCall, r.msg.Op())
		call := r.msg.(*CallMessage)
		require.Len(t, call.ObjectArgs, 1)
	case <-time.After(2 * time.Second):
		t.Fatal("Decoder.Next failed to return after pipe close")
	}
}
