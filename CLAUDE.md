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

Read-only parser for a single direction of a JRMP Stream-protocol (`0x4B`) byte stream. Consumes either a client→server or server→client capture and produces a `Transmission` tree: optional `Handshake` (client side) or `Acknowledge` (server side), optional `ClientEndpoint` echo, then a `Messages []Message` list.

**Three entry points, one parser.** `FromBytes(data []byte)`, `FromStream(r io.Reader)`, and `Decoder` (via `NewDecoder(r)` + `Opening()` + `Next()`) all delegate to the same underlying `readMessage` / `readOpening` primitives. No `streaming` flag on the core readers — each frame's arg strategy is picked from the frame's own header, not from the input source.
- `rmi.FromBytes(data []byte)` — whole-Transmission, buffered input. Loops until `io.EOF`.
- `rmi.FromStream(io.Reader)` — whole-Transmission, live input. Loops until the reader returns `io.EOF`. Blocks on the reader between frames; supports every frame type (not just Registry), with the blocking caveat documented in "Arg-reading strategy" below.
- `rmi.Decoder` (`rmi/decoder.go`) — frame-by-frame, live input. `Opening()` reads the optional handshake prefix; `Next()` returns one `Message` per call or `io.EOF`. The idiomatic API for live `net.Conn` consumers who want to apply `SetReadDeadline` between frames.

Both streaming paths rely on `serz.NewObjectStreamFromStream(*commons.Stream)` so the embedded serialization parse shares a byte cursor with the outer framing reader — no double-buffering, no peeked-byte loss at handoff.

**Arg-reading strategy inside `readCallArgs` / `readReturn`.**
- *Registry fast path* (ObjID == `REGISTRY_ID` AND `methodHash == RegistryInterfaceHash` AND op ∈ [0..4]): exact-count via `registryArgCount(op)`. Reads precisely N TCContents and returns — no peek past the last arg, so the parser returns as soon as the frame's own bytes arrive. Critical for live TCP: a Registry client that sends one Call and waits for the server's response would deadlock any peek-ahead scheme.
- *Sentinel fallback* (non-Registry Calls, ReturnData payloads): read TCContents until `PeekN(1)` yields a byte outside `[JAVA_TC_BASE, JAVA_TC_MAX]` (= `[0x70, 0x7F]`) or `io.EOF`. TC_* and JRMP-flag (`[0x50, 0x54]`) ranges are disjoint, so the check is unambiguous. **On a live reader the terminating peek blocks** until the next frame's flag byte arrives, the peer closes (`io.EOF`), or the reader's deadline fires. Callers that need responsiveness on non-Registry frames must set `SetReadDeadline` on the underlying `net.Conn`.

Every JRMP frame implements `Message` (`Op() byte` + `ToString() string`). Five frame types:

- **`CallMessage`** (0x50) — wraps an embedded serialization stream. The first `TC_BLOCKDATA` holds 34 bytes of primitive writes (`ObjID(22) + int32 op + int64 methodHash`). Remaining `TCContent` entries are `writeObject` arguments. `Decoded` is filled when `ObjID.IsRegistry()` **and** `methodHash == RegistryInterfaceHash` **and** the op-index is one of the five known Registry ops; otherwise `Raw` and `ObjectArgs` hold the untouched tree. `ToString()` renders the stream in wireshark-dissector style — see the rendering note below.
- **`ReturnMessage`** (0x51) — same embedded-stream shape, 15 bytes of primitives (`returnType + UID`) then ≤1 payload `TCContent` (value / exception / none-for-void).
- **`PingMessage`** (0x52), **`PingAckMessage`** (0x53) — single-byte frames, no payload.
- **`DgcAckMessage`** (0x54) — raw 14-byte UID written outside any `ObjectOutputStream` framing (the only JRMP frame that does *not* go through `serz`).

**The critical design point worth internalizing**: a single Java serialization stream has no explicit end marker — `serz.FromReader` terminates only on `io.EOF`. Inside JRMP, the next byte after a Call/Return body is the next message's flag (`0x50..0x54`), which is neither `io.EOF` nor a valid `TC_*` tag. The sentinel branches of `readCallArgs` (`rmi/call.go`) and `readReturn` (`rmi/return.go`) walk `serz.ReadTCContent` in a loop and stop when `PeekN(1)` returns a byte outside `[serz.JAVA_TC_BASE, serz.JAVA_TC_MAX]` = `[0x70, 0x7F]`. **Do not refactor this to use `serz.FromBytes`** — doing so would fail on any stream with more than one frame.

**Registry dispatch is op-index + interface hash, not per-method hash.** The JDK ships a precompiled `sun.rmi.registry.RegistryImpl_Stub` whose wire format is `operation = 0..4` (indexing into `{bind, list, lookup, rebind, unbind}`) paired with a single `int64 RegistryInterfaceHash` shared by all five methods. Modern JRMP's `operation = -1 + per-method hash` pattern applies only to dynamic-proxy stubs and is NOT used by Registry. `rmi/model.go` exposes the five op-index constants (`LookupOpIndex`, etc.) and the `RegistryInterfaceHash` constant (calibrated against a live Zulu OpenJDK 17 capture; see `testcases/rmi/*.bin` and `_tools/rmi-capture/`). If a real capture's `CallMessage.Decoded` is nil for an obvious Registry call, print `MethodHash` as hex and compare — recalibration is a one-line edit.

Adding a new message type (e.g. if SingleOp/Multiplex support is ever added): extend the `MsgXxx` constants in `model.go`, define `*XxxMessage` implementing `Message`, add a case to the `switch` in `rmi/message.go:readMessage`. The dispatcher is the single extension point.

The endpoint-echo heuristic in `parser.go:maybeReadClientEndpoint` peeks the byte right after the handshake: if it falls in `[0x50, 0x54]` (JRMP message flag range) we skip the echo, otherwise read `writeUTF + int32`. This lets hand-crafted test fixtures omit the echo. The ambiguity only collides on pathological (≥ 20480-char) hostnames.

**Live-TCP ergonomics.** `FromStream` loops internally until `io.EOF` — fine for bounded streams (`io.Pipe`, `bytes.Reader`) but a trap on a long-lived `net.Conn` where the peer keeps the connection open between frames. For live connections, use `Decoder` (`rmi/decoder.go`):

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

`Decoder.Next()` returns one frame per call. Registry Calls return as soon as their own bytes arrive (exact count, no peek past last arg). Non-Registry Calls and ReturnData use the sentinel, which blocks after the last arg/payload until either the next frame's flag byte arrives or the reader returns an error (EOF, read timeout from `SetReadDeadline`, etc.). The caller is responsible for configuring the deadline appropriate to their workload — the parser doesn't invent one.

`Opening()` is optional; if omitted, the first `Next()` transparently consumes and discards any handshake prefix. Calling `Opening()` twice, or after `Next()`, returns an error.

`serz.NewObjectStreamFromStream(s *commons.Stream) *ObjectStream` is the primitive all three entry points stand on — it lets an embedded serialization parse share a `commons.Stream` byte cursor with its caller, avoiding the double-buffering trap where bytes peeked into one layer get lost at handoff.

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
