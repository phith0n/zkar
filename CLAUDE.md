# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

ZKar is a pure-Go parser, viewer, and manipulator for the Java Object Serialization protocol (the `0xACED 0x0005` stream produced by `ObjectOutputStream`). No CGO or JDK is required. A `class` package for parsing `.class` bytecode, an `rmi` package for parsing the JRMP wire protocol, and a CLI (`main.go`) are also part of the repo. The project ships as both a library (`github.com/phith0n/zkar/serz`, `.../class`, `.../rmi`, `.../commons`) and a CLI binary released via goreleaser.

## Common commands

```shell
# Run the CLI
go run main.go dump -f testcases/ysoserial/CommonsCollections6.ser
go run main.go dump -B <base64-payload>
go run main.go dump --jdk8u20 -f testcases/pwntester/JDK8u20.ser   # see JDK8u20 note below
go run main.go dump --golang -f <file>                             # emits a Go literal via litter
go run main.go rmi  -f <jrmp-capture.bin>                          # parses JRMP framing; see rmi/ section

# Full test suite (also prints the README's gadget table to stdout as a side effect of TestMain)
go test -v ./...
go test -race ./...

# Single test / package
go test ./serz -run TestYsoserial -v
go test ./serz -run TestCC6WithOverlongEncoding -v

# Lint (CI uses golangci-lint latest; config in .golangci.yml)
golangci-lint run --verbose
```

CI matrix runs on Go 1.18–1.22 across Linux/macOS/Windows; keep code compatible with Go 1.18 (module `go 1.18`). Release tags `v*` trigger goreleaser.

## Architecture

### `serz` — the Java serialization codec

Every Java serialization stream is a magic number + version + a list of `TCContent` records. The parser is a recursive-descent reader over a byte stream; every on-wire grammar element has a Go type whose name matches the Java spec (`TCObject`, `TCClassDesc`, `TCProxyClassDesc`, `TCArray`, `TCString`, `TCEnum`, `TCReference`, `TCNull`, `TCBlockData`, `TCClass`, `TCFieldDesc`, `TCValue`, `TCUtf`, `TCClassPointer`, `TCStringPointer`). Follow that naming when adding grammar.

Key contracts:

- **`Object` interface** (`serz/model.go`-adjacent, defined in `parser.go`): every grammar node implements `ToBytes() []byte`, `ToString() string`, and `Walk(WalkCallback) error`. `ToBytes` must be a faithful round-trip of what was parsed — the test suite asserts `bytes.Equal(original, ser.ToBytes())` for every ysoserial fixture. Do not "normalize" output.
- **`TCContent`** (`serz/tc_content.go`) is the tag-dispatcher. Its `Flag` field selects which of the sibling pointers is populated, and `ToBytes`/`ToString`/`Walk`/`ReadTCContent` all fan out via the same `switch` on `Flag`. When you add a new `JAVA_TC_*` tag you must extend all four switch statements plus `serz/model.go` constants.
- **`ObjectStream`** (`serz/buffer.go`) wraps `commons.Stream` and owns the handler table. Every referenceable object (object, class, class desc, proxy class desc, string, array, enum) must call `stream.AddReference(obj)` at the point Java would assign it a wire handle (starting at `JAVA_BASE_WRITE_HANDLE = 0x7e0000`). `TCReference` resolves back via `GetReference`. Mis-ordering `AddReference` calls silently corrupts payloads — order them exactly where the Java writer would.
- **`Walk` / `FindObject` / `FindClassDesc`** (`serz/walker.go`) provide a generic visitor over the tree. `FindObject` aborts traversal by returning a sentinel `*StopWalkError`; preserve that pattern for short-circuit searches. `TestCC6WithOverlongEncoding` is the canonical example of mutating a parsed tree and re-serializing.
- **`serz/builder.go`** holds hand-written constructors (`NewTCString`, `SimpleClassDesc`, `NewTCValueBytes`, …) for programmatically building payloads. Prefer extending these over ad-hoc struct literals at call sites.
- **`DumpToGoStruct`** (`serz/go-dumper.go`) renders a parsed tree as Go source using a forked `litter`. `[]*TCValue` byte arrays are special-cased to emit `zkar.NewTCValueBytes([]byte("\x..."))` — keep that helper in sync if `TCValue` changes.

### Special cases worth knowing

- **JDK8u20**: the pwntester JDK8u20 gadget is not a valid serialization stream. `FromJDK8u20Bytes` / `ToJDK8u20Bytes` (`serz/parser.go`) patch a single `TC_ENDBLOCKDATA` (`0x78`) byte after the sequence `00 7e 00 09` on the way in and strip it on the way out. The CLI exposes this via `--jdk8u20`.
- **UTF-8 overlong encoding** (`serz/tc_utf.go`): `TCUtf.OverlongSize` lets you re-emit strings as 2- or 3-byte overlong sequences while still round-tripping when read. `fromOverlongEncoding` is intentionally lenient — it falls through to the original byte if the multi-byte pattern doesn't match.
- **`TC_RESET`** (`0x79`) resets the handler table on read. The `TCContent` dispatcher treats it as a first-class content; do not coalesce it with adjacent records.

### `rmi` — JRMP (Java RMI) wire-protocol parser

Read-only parser for a single direction of a JRMP Stream-protocol (`0x4B`) byte stream **addressed at `java.rmi.registry.Registry`**. Consumes either a client→server or server→client capture and produces a `Transmission` tree: optional `Handshake` (client side) or `Acknowledge` (server side), optional `ClientEndpoint` echo, then a `Messages []Message` list.

**Scope: Registry only.** This module deliberately supports only one Remote interface — the well-known `sun.rmi.registry.RegistryImpl_Stub`. Any `MsgCall` whose header doesn't pass the dispatch gate (ObjID == `REGISTRY_ID` **and** methodHash == `RegistryInterfaceHash` **and** op ∈ [0..4]) is rejected at parse time in `readCall`. Non-Registry Remote interfaces each have their own method-hash table that we don't carry, and the project's use case (intercepting `rmiregistry` traffic for exploitation or analysis) is fully served by Registry coverage. If you need a general JRMP parser, this is not it.

**Two entry points.** Pick by input shape, not by input source:
- `rmi.FromBytes(data []byte)` — for bytes already in memory (`.bin` captures, `io.ReadAll` of an HTTP body, etc.). Loops until `io.EOF` and returns the whole `Transmission`. **Never use with a live `net.Conn`**: the loop blocks on the next `PeekN(1)` after the last frame and deadlocks when the peer stays open waiting for a reply — which is the typical synchronous-RPC pattern.
- `rmi.Decoder` (`rmi/decoder.go`) — frame-by-frame, for live readers. `NewDecoder(r)` wraps any `io.Reader`; `Opening()` consumes the optional handshake prefix; `Next()` returns one `Message` per call or `io.EOF`. This is the only sensible choice for a long-lived TCP connection: callers apply `SetReadDeadline` on the underlying `net.Conn` between `Next()` calls to bound how long they wait for the next frame.

Both rely on `serz.NewObjectStreamFromStream(*commons.Stream)` so the embedded serialization parse shares a byte cursor with the outer framing reader — no double-buffering, no peeked-byte loss at handoff.

**Arg/payload-reading strategy.**
- `readCallArgs` — **exact count, no peek**. Once `readCall` passes the Registry dispatch gate, `registryArgCount(op)` gives the stub method's known arity, and `readCallArgs` reads precisely that many TCContents. The parser returns as soon as the frame's own bytes arrive — critical on a live TCP reader where a Registry client sends one Call and then waits for the server's response before sending anything else. A peek-ahead scheme would deadlock.
- `readReturn` — **sentinel**. Payload count is 0 (void method: bind/rebind/unbind) or 1 (list/lookup value / exception Throwable), and that choice depends on the originating Call's return type. Direction-agnostic parsing can't correlate Returns to outstanding Calls, so we fall back to a sentinel: read TCContents until `PeekN(1)` yields a byte outside `[JAVA_TC_BASE, JAVA_TC_MAX]` (= `[0x70, 0x7F]`) or `io.EOF`; assert count ≤ 1. TC_* and JRMP-flag (`[0x50, 0x54]`) ranges are disjoint, so the check is unambiguous. **On a live reader the terminating peek blocks** until the next frame's flag byte arrives, the peer closes (`io.EOF`), or the reader's deadline fires. Callers that process Returns over a live connection must set `SetReadDeadline` on the underlying `net.Conn`.

Every JRMP frame implements `Message` (`Op() byte` + `ToString() string`). Five frame types:

- **`CallMessage`** (0x50) — wraps an embedded serialization stream. The first `TC_BLOCKDATA` holds 34 bytes of primitive writes (`ObjID(22) + int32 op + int64 methodHash`). Remaining `TCContent` entries are the method arguments. On a successful parse, `Operation` is always one of the five `{Bind, List, Lookup, Rebind, Unbind}OpIndex` constants and `Decoded` is populated; a non-fatal decoder error (e.g. malformed string arg) can still leave `Decoded` nil while `Raw` / `ObjectArgs` hold the raw tree. `ToString()` renders the stream in wireshark-dissector style — see the rendering note below.
- **`ReturnMessage`** (0x51) — same embedded-stream shape, 15 bytes of primitives (`returnType + UID`) then ≤1 payload `TCContent` (value / exception / none-for-void).
- **`PingMessage`** (0x52), **`PingAckMessage`** (0x53) — single-byte frames, no payload.
- **`DgcAckMessage`** (0x54) — raw 14-byte UID written outside any `ObjectOutputStream` framing (the only JRMP frame that does *not* go through `serz`).

**The critical design point worth internalizing**: a single Java serialization stream has no explicit end marker — `serz.FromReader` terminates only on `io.EOF`. Inside JRMP, the next byte after a Return body is the next message's flag (`0x50..0x54`), which is neither `io.EOF` nor a valid `TC_*` tag. The sentinel in `readReturn` (`rmi/return.go`) walks `serz.ReadTCContent` and stops when `PeekN(1)` returns a byte outside `[serz.JAVA_TC_BASE, serz.JAVA_TC_MAX]`. **Do not refactor this to use `serz.FromBytes`** — doing so would fail on any stream with more than one frame. (Calls don't need the sentinel because `registryArgCount` gives the exact count.)

**Registry dispatch is op-index + interface hash, not per-method hash.** The JDK ships a precompiled `sun.rmi.registry.RegistryImpl_Stub` whose wire format is `operation = 0..4` (indexing into `{bind, list, lookup, rebind, unbind}`) paired with a single `int64 RegistryInterfaceHash` shared by all five methods. Modern JRMP's `operation = -1 + per-method hash` pattern applies only to dynamic-proxy stubs and is NOT used by Registry. `rmi/model.go` exposes the five op-index constants (`LookupOpIndex`, etc.) and the `RegistryInterfaceHash` constant (calibrated against a live Zulu OpenJDK 17 capture; see `testcases/rmi/*.bin` and `_tools/rmi-capture/`). If a real Registry capture starts failing the hash check after a JDK upgrade, print `MethodHash` as hex and recalibrate — it's a one-line edit.

Adding a new message type (e.g. if SingleOp/Multiplex support is ever added): extend the `MsgXxx` constants in `model.go`, define `*XxxMessage` implementing `Message`, add a case to the `switch` in `rmi/message.go:readMessage`. The dispatcher is the single extension point.

The endpoint-echo heuristic in `parser.go:maybeReadClientEndpoint` peeks the byte right after the handshake: if it falls in `[0x50, 0x54]` (JRMP message flag range) we skip the echo, otherwise read `writeUTF + int32`. This lets hand-crafted test fixtures omit the echo. The ambiguity only collides on pathological (≥ 20480-char) hostnames.

**Live-TCP ergonomics.** On a long-lived `net.Conn` a typical Registry session has the shape handshake → Call → (peer waits for Return) → Return → close. `FromBytes` would deadlock on the second peek after the first frame; `Decoder` is the only viable choice. For *client-side* reading (capture already in hand, or reading responses from a server), the one-shot `Opening()` is fine:

```go
d := rmi.NewDecoder(conn)
opening, _ := d.Opening()       // optional — read handshake/ack/endpoint
for {
    _ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
    msg, err := d.Next()
    if errors.Is(err, io.EOF) { break }
    if err != nil { return err }
    handle(msg)
}
```

*Server-side `Opening()` deadlocks.* A conforming Java client (`sun.rmi.transport.tcp.TCPChannel`) writes the 7-byte handshake and then blocks reading the server's `ProtocolAck` before writing its `ClientEndpoint` echo. `Opening()` consumes handshake + endpoint in one call, so its second peek waits for bytes the client refuses to send until the server writes the Ack. For servers (and any caller that must inject writes into the handshake phase), use the fine-grained primitives:

```go
d := rmi.NewDecoder(conn)
hs, err := d.ReadHandshake()      // consumes only the 7-byte handshake
// ... write the Ack to conn before reading further ...
remote := conn.RemoteAddr().(*net.TCPAddr)
_, _ = conn.Write((&rmi.Acknowledge{Host: remote.IP.String(), Port: int32(remote.Port)}).ToBytes())
ep, err := d.ReadClientEndpoint() // now safe: client unblocks after reading Ack
for {
    _ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
    msg, err := d.Next()
    ...
}
```

`ReadAcknowledge()` is the symmetric client-side primitive. The three opening primitives and `Opening()` are **mutually exclusive** — the Decoder tracks a stage (`stageInitial` → `stageAfterHandshake` → `stageReady`) and refuses out-of-order calls. `Next()` auto-advances to `stageReady` from either earlier stage (auto-consuming a `ClientEndpoint` after `ReadHandshake` if the caller skipped `ReadClientEndpoint`), so omitting the opening entirely still works for bare captures.

`Handshake`, `Acknowledge`, and `Endpoint` all expose `ToBytes()` for writing: zero-valued `Magic`/`Protocol`/`Flag` fields default to `JRMI_MAGIC` / `ProtocolStream` / `AckFlag`, so server code can usually construct with just `Host` + `Port` (see `TestOpeningEncodersRoundTrip` for the exact layouts).

`Decoder.Next()` returns one frame per call. Registry Calls return as soon as their own bytes arrive (no peek past last arg). ReturnData uses the sentinel and may block between frames on a live reader until the next flag byte arrives or the reader's deadline fires — the caller is responsible for the deadline.

**`ToString()` rendering is wireshark-dissector style — every byte is printed exactly once, with semantic labels inline.** `Call/ReturnMessage.ToString()` emits a compact `@Decoded` summary (method + scalar args; complex args referenced by handler) at the top, then `@Serialization` with a custom walk (`rmi/printer.go`):

- The leading `TC_BLOCKDATA` that carries the Call's 34-byte `ObjID + op + hash` (or the Return's 15-byte `returnType + UID`) is replaced in-place with its decomposed fields, each showing both decimal *and* the matching byte slice.
- Every subsequent `TCContent` arg has its header line annotated: `TC_STRING - 0x74  (Registry.lookup arg 0: "name")`, `TC_OBJECT - 0x73  (Registry.bind arg 1: "obj")`.
- Remote-stub TCContent subtrees (bind/rebind `obj`) appear exactly once, inside `@Serialization`; `@Decoded.Args` references them by handler — **do not reintroduce full-subtree dumping in `DecodedCall.ToString`**, that's the duplication this layout fixes.

Fields outside `@Serialization` (`Handshake.Magic/Version/Protocol`, `Acknowledge`/`ClientEndpoint.Host/Port`) keep their raw hex because no other section carries those bytes.

### `class` — JVM `.class` parser

Parses the `0xCAFEBABE` class-file format. `ClassFile.readXxx` methods are sequenced in `class/parser.go`. Each constant-pool tag, attribute, and annotation element has its own file (`constant_*.go`, `attr_*.go`); when adding support for a new attribute, create a new file rather than stuffing it into an existing one — this matches the existing convention. The parser is currently incomplete (methods/attributes reader is a WIP per README TODO), and `TestParseClass` is `SkipNow()`'d.

### `commons` — shared primitives

- `Stream` / `ObjectStream`: buffered byte reader with `PeekN`, `ReadN`, `Seek`, `CurrentIndex`. All parsers read through this.
- `Printer`: indent-aware `strings.Builder` wrapper. `ToString()` methods build output via `NewPrinter()` + `IncreaseIndent()`/`DecreaseIndent()`; keep that style for consistency with the human-readable dump format shown in the asciinema demo.
- `NumberToBytes` / `Hexify`: big-endian encoding and hex-with-spaces formatting used throughout `ToBytes`/`ToString`.

## Testing conventions

- `testcases/ysoserial/*.ser` and `testcases/pwntester/*.ser` are the ground-truth fixtures. Any change to `serz` must keep `TestYsoserial` and `TestJDK8u20` green, and those tests assert **byte-exact** round-trip (`FromBytes` → `ToBytes` must equal the original file).
- `testcases/rmi/<jdk>/*.bin` are JRMP captures produced by `_tools/rmi-capture/capture.sh` against a real `rmiregistry` (current subdirs: `jdk17/`, `jdk8/`). `rmi/integration_test.go` loads each one via `forEachJDK`, running every assertion as a subtest per JDK to catch wire-format drift. The captures for the five Registry methods are byte-identical across JDK 8 and 17 except for runtime-unique bits (UIDs, ports); only the server-side exception returns differ in the serialized `Throwable`'s embedded class metadata (JDK 17 modules add ~113 bytes). The `_tools/` directory is ignored by the Go toolchain (leading underscore), so `go build ./...` / `go test ./...` won't try to compile the capture scripts.
- `TestMain` in `serz/parser_test.go` runs after the suite and prints the Markdown gadget table shown in the README. If you add a fixture, the table regenerates automatically; paste the new rows into `README.md` manually.
- Use `github.com/stretchr/testify/require` (already in go.mod) — match the existing `require.Nil` / `require.Equal` / `require.Truef` style.

## Conventions picked up from `.golangci.yml`

Enabled: `unused`, `errcheck`, `gosimple`, `govet`, `ineffassign`, `staticcheck` (all checks), `gofmt`, `goconst`, `misspell` (US locale), `nolintlint` (unused directives are errors), `tagliatelle`. `tagliatelle` enforces **snake_case** for `json`, `yaml`, `xml`, `form`, and `msgpack` struct tags — use snake_case when adding tags.
