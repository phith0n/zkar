#!/usr/bin/env bash
#
# Drives a local rmiregistry through a socat tee-proxy, producing per-op
# binary captures. Each operation runs in its own JVM against a fresh socat
# process, so every capture pair corresponds to exactly one TCP connection.
#
# Pre-reqs: socat, a JDK (we default to Zulu 17 if JAVA_HOME is unset).
#
# Env vars:
#   JAVA_HOME    JDK to use (default: Zulu 17)
#   JDK_LABEL    Sub-directory name under testcases/rmi/ to write into
#                (default: jdk17; use "jdk8" etc. to segregate fixtures
#                produced by different JDKs)
#
# Output layout (per op in: lookup, list, bind, rebind, unbind):
#   testcases/rmi/<JDK_LABEL>/<op>-c2s.bin   client → server bytes
#   testcases/rmi/<JDK_LABEL>/<op>-s2c.bin   server → client bytes

set -euo pipefail

JAVA_HOME="${JAVA_HOME:-/Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home}"
export PATH="$JAVA_HOME/bin:$PATH"

JDK_LABEL="${JDK_LABEL:-jdk17}"

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
OUT="$REPO/testcases/rmi/$JDK_LABEL"
mkdir -p "$OUT"
echo "--- JDK: $($JAVA_HOME/bin/java -version 2>&1 | head -1)"
echo "--- writing to $OUT"

REG_PID=""
SOCAT_PID=""
cleanup() {
    set +e
    [[ -n "$SOCAT_PID" ]] && kill "$SOCAT_PID" 2>/dev/null
    [[ -n "$REG_PID"   ]] && kill "$REG_PID"   2>/dev/null
    wait 2>/dev/null
}
trap cleanup EXIT

cd "$HERE"
echo "--- compiling Driver.java ---"
javac Driver.java

echo "--- starting rmiregistry on :1099 ---"
rmiregistry 1099 &
REG_PID=$!
sleep 1

for op in lookup list bind rebind unbind; do
    echo ""
    echo "=== $op ==="

    # Fresh one-shot socat per op:
    #   - TCP-LISTEN without fork accepts one connection then exits
    #   - SYSTEM runs a pipeline that tees both directions to files
    #     while an inner socat bridges to the real registry on :1099
    # socat 1.8 splits the SYSTEM argument on ':' as options, so the inner
    # address must escape its own colons (TCP\:localhost\:1099).
    socat TCP-LISTEN:1100,reuseaddr \
          SYSTEM:"tee '$OUT/$op-c2s.bin' | socat - TCP\\:localhost\\:1099 | tee '$OUT/$op-s2c.bin'" &
    SOCAT_PID=$!
    sleep 0.3

    java -cp "$HERE" Driver "$op" 1100 || true

    # Wait for the one-shot socat to exit naturally after the JVM's socket closes.
    wait $SOCAT_PID 2>/dev/null || true
    SOCAT_PID=""
done

echo ""
echo "--- captures in $OUT ---"
ls -la "$OUT"
