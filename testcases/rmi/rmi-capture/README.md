# rmi-capture

Tools for regenerating the JRMP byte-stream fixtures under `testcases/rmi/`,
used by `rmi/integration_test.go`.

## Pre-reqs

- `socat` >= 1.8
- A JDK with `rmiregistry` (defaults to Zulu 17 at
  `/Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home`; override via
  `JAVA_HOME`)

## Usage

```
# Default: Zulu 17 → testcases/rmi/jdk17/
./capture.sh

# Any other JDK:
JAVA_HOME=/Library/Java/JavaVirtualMachines/zulu-8.jdk/Contents/Home \
JDK_LABEL=jdk8 \
./capture.sh
```

The `JDK_LABEL` env var controls the subdirectory under `testcases/rmi/`. Pick
a name that matches the tested JDK so `rmi/integration_test.go` can reference
it from its `fixtureJDKs` list.

This:

1. Compiles `Driver.java` (a one-shot RMI client).
2. Starts a local `rmiregistry` on :1099.
3. For each op in `{lookup, list, bind, rebind, unbind}`:
   - Starts a one-shot `socat` tee-proxy on :1100 → :1099.
   - Runs `Driver <op> 1100` in a fresh JVM (each invocation uses a new TCP
     connection, so one op per capture pair).
   - socat writes every byte in each direction to
     `testcases/rmi/<op>-{c2s,s2c}.bin`.
4. Cleans up the registry/proxy via a shell `trap`.

## Why a custom socat command

socat's `-x -v` verbose mode spits hex to stderr but not in a form that's
trivial to convert back to bytes. Instead we plumb both directions through
`tee` using socat's `SYSTEM:` address, getting one clean binary file per
direction per op:

```
socat TCP-LISTEN:1100,reuseaddr \
      SYSTEM:"tee '<c2s>' | socat - TCP\:localhost\:1099 | tee '<s2c>'"
```

The escaped colons matter: **socat 1.8 splits the `SYSTEM:` argument on `:`**,
so the inner `TCP:localhost:1099` address would be mis-parsed without
`TCP\:localhost\:1099`.

## Why one JVM per op

Java's RMI transport keeps connections alive and reuses them across calls
from the same JVM. Running all five ops in one JVM would produce a single
`<c2s>` file with five Calls interleaved with the registry's DGC traffic,
making per-op assertions harder. A fresh JVM per op costs ~1s and yields one
handshake + one Call + one ReturnData per capture file.

## Host/port in captures

The `Handshake` + `ClientEndpoint` bytes embed the capture machine's
hostname/IP. `rmi/integration_test.go` asserts only that the fields are
present and well-formed, not their concrete values, so captures are
regenerable on any machine.
