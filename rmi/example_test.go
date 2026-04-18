package rmi_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/phith0n/zkar/rmi"
)

// ExampleFromBytes parses a fully-buffered JRMP capture — the common case
// for post-mortem analysis of a .bin file produced by Wireshark's
// follow-tcp-stream or similar tooling.
//
// The capture used here is a single Registry.lookup("ghost") call against a
// live rmiregistry (see testcases/rmi/jdk17/). After FromBytes the parser
// has already decoded the Registry dispatch — no further bookkeeping is
// needed to get method name + arg values.
func ExampleFromBytes() {
	data, err := os.ReadFile(filepath.Join("..", "testcases", "rmi", "jdk17", "lookup-c2s.bin"))
	if err != nil {
		fmt.Println("read fixture:", err)
		return
	}

	tr, err := rmi.FromBytes(data)
	if err != nil {
		fmt.Println("parse:", err)
		return
	}

	// A client→server capture opens with a JRMI handshake followed by the
	// client's endpoint echo.
	fmt.Println("handshake version:", tr.Handshake.Version)
	fmt.Println("endpoint present:", tr.ClientEndpoint != nil)
	fmt.Println("message count:", len(tr.Messages))

	// Every message surfaces as the narrow Message interface; a type switch
	// lifts it back to the concrete CallMessage / ReturnMessage / … kind.
	call := tr.Messages[0].(*rmi.CallMessage)
	fmt.Println("method:", call.Decoded.Method)
	fmt.Printf("arg: %s=%q\n", call.Decoded.Args[0].Name, call.Decoded.Args[0].Value)

	// Output:
	// handshake version: 2
	// endpoint present: true
	// message count: 1
	// method: Registry.lookup
	// arg: name="ghost"
}

// ExampleNewDecoder demonstrates the frame-by-frame API — the right choice
// for long-lived connections where the caller wants to apply
// SetReadDeadline between frames or process one message before the next
// arrives.
//
// Opening() consumes the handshake-phase prefix (handshake / ack / client
// endpoint). Next() returns one Message per call, surfacing io.EOF when
// the reader closes cleanly at a frame boundary.
func ExampleNewDecoder() {
	data := []byte{
		0x4A, 0x52, 0x4D, 0x49, 0x00, 0x02, 0x4B, // handshake
		0x52, // Ping
		0x53, // PingAck
		0x52, // Ping
	}

	d := rmi.NewDecoder(bytes.NewReader(data))

	opening, err := d.Opening()
	if err != nil {
		fmt.Println("opening:", err)
		return
	}
	fmt.Println("handshake present:", opening.Handshake != nil)

	for {
		msg, err := d.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			fmt.Println("next:", err)
			return
		}
		fmt.Printf("frame: 0x%02X\n", msg.Op())
	}

	// Output:
	// handshake present: true
	// frame: 0x52
	// frame: 0x53
	// frame: 0x52
}

// ExampleDecoder_liveConnection sketches the pattern for reading JRMP
// traffic off a live net.Conn — the only supported way to parse from a
// long-lived TCP connection. The two things to notice are (a) the caller
// applies SetReadDeadline between frames to bound how long to wait for
// the next one, and (b) non-Registry Call headers and Return sentinel
// timeouts surface as normal errors the caller can inspect.
//
// This example does not connect to a real server; it's structured as a
// compile-check so the idiom stays accurate as the API evolves.
func ExampleDecoder_liveConnection() {
	// In real code: conn, err := net.Dial("tcp", "rmiregistry:1099")
	// For this example we reuse an in-memory reader so the body compiles
	// and runs without a server.
	var conn io.Reader = bytes.NewReader([]byte{
		0x4A, 0x52, 0x4D, 0x49, 0x00, 0x02, 0x4B, // handshake
		0x52, // Ping
	})

	d := rmi.NewDecoder(conn)
	if _, err := d.Opening(); err != nil {
		fmt.Println("opening:", err)
		return
	}

	for {
		// On a real net.Conn:
		//   conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		msg, err := d.Next()
		if errors.Is(err, io.EOF) {
			fmt.Println("peer closed")
			return
		}
		if err != nil {
			// Deadline errors from a net.Conn land here; so do
			// non-Registry Call rejections and any malformed-frame errors.
			fmt.Println("next:", err)
			return
		}
		fmt.Printf("got frame 0x%02X\n", msg.Op())
	}

	// Output:
	// got frame 0x52
	// peer closed
}
