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

// TestDecoderRejectsNonRegistryCall: a Call whose header fails the Registry
// dispatch gate errors out at parse time. Decoder's Next() surfaces the
// error directly — no sentinel, no blocking.
func TestDecoderRejectsNonRegistryCall(t *testing.T) {
	nonReg := ObjID{ObjNum: 42, UID: UID{Unique: 1, Time: 2, Count: 3}}
	data := buildCall(nonReg, LookupOpIndex, RegistryInterfaceHash, buildTCString("x"))

	d := NewDecoder(bytes.NewReader(data))
	_, err := d.Next()
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a Registry call")
}

// TestDecoderServerFlowWithInterleavedAck reproduces the real rmiregistry
// server timing: a standard Java client sends its 7-byte handshake and
// then BLOCKS until the server writes a ProtocolAck — only after reading
// the Ack does it send its ClientEndpoint echo. Opening() would deadlock
// on this shape because it reads handshake and endpoint in a single call.
// The server-side flow (ReadHandshake → write Ack → ReadClientEndpoint →
// Next) must complete without blocking past what the client will send at
// each step.
func TestDecoderServerFlowWithInterleavedAck(t *testing.T) {
	// c2s: what the client writes. s2c: what the server writes (captured
	// here so we can assert the Ack bytes the server produced).
	c2sRead, c2sWrite := io.Pipe()
	s2cRead, s2cWrite := io.Pipe()

	clientDone := make(chan error, 1)
	// Client goroutine: mimic sun.rmi.transport.tcp.TCPChannel — write
	// handshake, read ack in full, then write endpoint + a Ping so the
	// server has a message to parse and we can verify the whole flow.
	go func() {
		defer func() { _ = c2sWrite.Close() }()
		if _, err := c2sWrite.Write(buildHandshake()); err != nil {
			clientDone <- err
			return
		}
		// Drain the server's Ack before writing anything else — this is
		// the critical ordering constraint. Ack = 1 flag + 2 length +
		// len("127.0.0.1")=9 + 4 port = 16 bytes for the fixture below.
		ack := make([]byte, 16)
		if _, err := io.ReadFull(s2cRead, ack); err != nil {
			clientDone <- err
			return
		}
		if _, err := c2sWrite.Write(buildClientEndpointEcho("client.local", 55555)); err != nil {
			clientDone <- err
			return
		}
		if _, err := c2sWrite.Write(buildPing()); err != nil {
			clientDone <- err
			return
		}
		clientDone <- nil
	}()

	d := NewDecoder(c2sRead)

	// Stage 1: read just the handshake. Must return as soon as 7 bytes
	// arrive — a peek past that would block.
	hs, err := d.ReadHandshake()
	require.NoError(t, err)
	require.Equal(t, uint16(2), hs.Version)
	require.Equal(t, ProtocolStream, hs.Protocol)

	// Stage 2: server writes its Ack. Without this step the client will
	// sit forever on its io.ReadFull and the next ReadClientEndpoint
	// would deadlock.
	ack := &Acknowledge{Host: "127.0.0.1", Port: 1234}
	go func() {
		_, _ = s2cWrite.Write(ack.ToBytes())
		_ = s2cWrite.Close()
	}()

	// Stage 3: consume the post-Ack endpoint echo.
	ep, err := d.ReadClientEndpoint()
	require.NoError(t, err)
	require.NotNil(t, ep)
	require.Equal(t, "client.local", ep.Host)
	require.Equal(t, int32(55555), ep.Port)

	// Stage 4: messages flow normally from here.
	msg, err := d.Next()
	require.NoError(t, err)
	require.Equal(t, MsgPing, msg.Op())

	select {
	case err := <-clientDone:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("client goroutine stalled — server flow did not advance as expected")
	}
}

// TestDecoderOpeningAfterReadHandshakeErrors: the three opening-phase
// entry points are mutually exclusive. Once ReadHandshake has committed
// the Decoder to the fine-grained flow, Opening() is no longer valid.
func TestDecoderOpeningAfterReadHandshakeErrors(t *testing.T) {
	d := NewDecoder(bytes.NewReader(buildHandshake()))
	_, err := d.ReadHandshake()
	require.NoError(t, err)
	_, err = d.Opening()
	require.Error(t, err)
}

// TestDecoderReadHandshakeAfterOpeningErrors: symmetric — once Opening has
// finished the opening phase, none of the Read* primitives may run.
func TestDecoderReadHandshakeAfterOpeningErrors(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(buildHandshake())
	buf.Write(buildClientEndpointEcho("h", 1))
	d := NewDecoder(&buf)
	_, err := d.Opening()
	require.NoError(t, err)
	_, err = d.ReadHandshake()
	require.Error(t, err)
}

// TestDecoderReadClientEndpointRequiresHandshake: the endpoint primitive
// has no way to locate itself in the stream without the preceding
// handshake read — guard against callers skipping the prerequisite.
func TestDecoderReadClientEndpointRequiresHandshake(t *testing.T) {
	d := NewDecoder(bytes.NewReader(buildClientEndpointEcho("h", 1)))
	_, err := d.ReadClientEndpoint()
	require.Error(t, err)
}

// TestDecoderNextAutoConsumesClientEndpoint: if a server calls
// ReadHandshake but then skips ReadClientEndpoint (e.g. doesn't care
// about the echo), Next() should transparently consume the echo before
// parsing the first message.
func TestDecoderNextAutoConsumesClientEndpoint(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(buildHandshake())
	buf.Write(buildClientEndpointEcho("h", 1))
	buf.Write(buildPing())

	d := NewDecoder(&buf)
	_, err := d.ReadHandshake()
	require.NoError(t, err)

	msg, err := d.Next()
	require.NoError(t, err)
	require.Equal(t, MsgPing, msg.Op())
}

// TestDecoderReadAcknowledge: client-side flow — read the server's Ack
// as the first call, then message traffic.
func TestDecoderReadAcknowledge(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(buildAck("1.2.3.4", 4242))
	buf.Write(buildPing())

	d := NewDecoder(&buf)
	ack, err := d.ReadAcknowledge()
	require.NoError(t, err)
	require.Equal(t, "1.2.3.4", ack.Host)
	require.Equal(t, int32(4242), ack.Port)

	msg, err := d.Next()
	require.NoError(t, err)
	require.Equal(t, MsgPing, msg.Op())
}

// TestOpeningEncodersRoundTrip: the new ToBytes encoders must produce the
// exact layout the fixture builders produce (and therefore the exact
// layout the parsers consume).
func TestOpeningEncodersRoundTrip(t *testing.T) {
	// Handshake: defaults on zero-valued Magic/Protocol.
	require.Equal(t, buildHandshake(), (&Handshake{Version: 2}).ToBytes())
	// Acknowledge: default-Flag path and explicit-Flag path both emit
	// the buildAck layout.
	require.Equal(t, buildAck("127.0.0.1", 1234), (&Acknowledge{Host: "127.0.0.1", Port: 1234}).ToBytes())
	require.Equal(t, buildAck("host", 9), (&Acknowledge{Flag: AckFlag, Host: "host", Port: 9}).ToBytes())
	// Endpoint: matches buildClientEndpointEcho.
	require.Equal(t, buildClientEndpointEcho("client.local", 55555),
		(&Endpoint{Host: "client.local", Port: 55555}).ToBytes())
}

// TestDecoderChunkedDelivery feeds a real rmiregistry capture through an
// io.Pipe in 7-byte chunks with tiny sleeps between, mimicking TCP
// segmentation where bytes arrive across multiple Read calls. A Decoder
// reading from the pipe must stitch the chunks together correctly across
// message-internal boundaries. A 5s guard catches any accidental block.
func TestDecoderChunkedDelivery(t *testing.T) {
	data := loadRMIFixture(t, "jdk17", "lookup-c2s.bin")
	pr, pw := io.Pipe()

	go func() {
		defer func() { _ = pw.Close() }()
		for i := 0; i < len(data); i += 7 {
			end := i + 7
			if end > len(data) {
				end = len(data)
			}
			_, _ = pw.Write(data[i:end])
			time.Sleep(1 * time.Millisecond)
		}
	}()

	type result struct {
		opening *Opening
		msg     Message
		err     error
	}
	done := make(chan result, 1)
	go func() {
		d := NewDecoder(pr)
		o, oerr := d.Opening()
		if oerr != nil {
			done <- result{err: oerr}
			return
		}
		m, merr := d.Next()
		done <- result{opening: o, msg: m, err: merr}
	}()

	select {
	case r := <-done:
		require.NoError(t, r.err)
		require.NotNil(t, r.opening.Handshake)
		require.Equal(t, MsgCall, r.msg.Op())
	case <-time.After(5 * time.Second):
		t.Fatal("Decoder did not return within 5s — likely blocked reading past the frame boundary")
	}
}
