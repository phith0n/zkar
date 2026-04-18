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

Read-only parser for a single direction of a JRMP Stream-protocol (`0x4B`) byte stream **addressed at `java.rmi.registry.Registry`**. Produces a `Transmission`: optional `Handshake` + `ClientEndpoint` (client→server) or `Acknowledge` (server→client), then `Messages []Message` (`CallMessage` / `ReturnMessage` / `PingMessage` / `PingAckMessage` / `DgcAckMessage`). Every frame satisfies `Message` (`Op() byte` + `ToString() string`).

**Scope: Registry only.** Any `MsgCall` whose header fails the dispatch gate (ObjID == `REGISTRY_ID` **and** methodHash == `RegistryInterfaceHash` **and** op ∈ [0..4]) is rejected at parse time in `readCall`. Registry uses the legacy `int32 operation = 0..4 + int64 RegistryInterfaceHash` form (op-index + shared interface hash); modern JRMP's `operation = -1 + per-method hash` is dynamic-proxy-stub only and NOT used here. `RegistryInterfaceHash` in `model.go` is calibrated against Zulu OpenJDK 17 — if it starts failing after a JDK upgrade, print `MethodHash` as hex and recalibrate (one-line edit). To add a new message type, extend `MsgXxx` in `model.go`, implement `Message`, add a case to `rmi/message.go:readMessage` — single extension point.

**Two entry points. Pick by input shape, not source.**
- `rmi.FromBytes(data []byte)` — fully-buffered captures only. **Deadlocks on a live `net.Conn`** (loops until EOF, the peek after the last frame blocks while the peer waits for a reply).
- `rmi.Decoder` — frame-by-frame over any `io.Reader`. Only sensible choice for live TCP. See the `Decoder` godoc for full usage.

**Opening phase has two live-reader traps.**

First, `Opening()` reads `Handshake + ClientEndpoint` in one call — **deadlocks on server-side reads** because a conforming Java client (`sun.rmi.transport.tcp.TCPChannel`) blocks after its 7-byte handshake waiting for the server's `ProtocolAck` before writing the endpoint echo. Servers must use the split primitives:

```go
hs, _ := d.ReadHandshake()                                              // 7 bytes only
_, _  = conn.Write((&rmi.Acknowledge{Host: h, Port: p}).ToBytes())      // unblocks client
ep, _ := d.ReadClientEndpoint()                                         // echo now arrives
```

`ReadAcknowledge()` is the symmetric client-side primitive. A stage enum (`stageInitial → stageAfterHandshake → stageReady`) enforces ordering; `Opening()` and the three `Read*` primitives are mutually exclusive. `Next()` auto-advances from any earlier stage to `stageReady`. `Handshake` / `Acknowledge` / `Endpoint` all expose `ToBytes()` with zero-value defaults (`JRMI_MAGIC` / `ProtocolStream` / `AckFlag`) so server code can skip those fields.

**Arg/payload reading strategies are not interchangeable.**
- `readCallArgs`: **exact count**, no peek. `registryArgCount(op)` gives the stub method's arity; the parser returns as soon as the frame's own bytes arrive — critical because a Registry client sends one Call and then waits for the Return before writing anything else.
- `readReturn`: **sentinel**. Payload count (0 for void bind/rebind/unbind, 1 for list/lookup/Throwable) depends on the originating Call, which direction-agnostic parsing can't correlate. So we peek after the 15-byte primitive header and stop when the next byte falls outside `[JAVA_TC_BASE, JAVA_TC_MAX]` (= `[0x70, 0x7F]`). Works because TC_* and JRMP-flag (`[0x50, 0x54]`) ranges are disjoint. **On live readers this peek blocks until the next frame's flag byte, EOF, or a read deadline fires** — callers must `SetReadDeadline`.

**Critical invariant.** A Java serialization stream has no end marker — `serz.FromReader` terminates only on EOF. Inside JRMP the byte after a Return body is the next message's flag (`0x50..0x54`), which is neither EOF nor a valid `TC_*` tag. **Do not refactor `readReturn` to use `serz.FromBytes`** — it would fail on any stream with more than one frame. (Calls don't need the sentinel because the arg count is known.)

**`ToString()` rendering is wireshark-dissector style — every byte is printed exactly once, semantic labels inline.** `Call/ReturnMessage.ToString()` emits a compact `@Decoded` summary at the top, then `@Serialization` via `rmi/printer.go`: the leading `TC_BLOCKDATA` is replaced by its decomposed primitive fields (decimal + hex for each), every subsequent `TCContent` arg gets an inline annotation (`TC_STRING - 0x74  (Registry.lookup arg 0: "name")`), and remote-stub subtrees appear **exactly once** inside `@Serialization` (referenced by handler in `@Decoded.Args`). **Do not reintroduce full-subtree dumping in `DecodedCall.ToString`** — that's the duplication this layout fixes.

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
