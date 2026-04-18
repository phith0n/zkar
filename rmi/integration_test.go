package rmi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phith0n/zkar/serz"
	"github.com/stretchr/testify/require"
)

func indexOf(haystack, needle string) int { return strings.Index(haystack, needle) }

// Integration tests against real rmiregistry byte captures under
// testcases/rmi/<jdk>/. Regenerate with:
//
//   bash _tools/rmi-capture/capture.sh                       # jdk17 (default)
//   JAVA_HOME=/path/to/jdk8 JDK_LABEL=jdk8 bash ...capture.sh
//
// Every Call / Return test runs once per JDK (subtests) to catch JDK-specific
// wire-format drift. Assertions intentionally ignore hostnames/ports/UIDs so
// captures regenerate cleanly across environments.

// fixtureJDKs enumerates every JDK whose captures we assert on. Add a new
// entry when capturing on a new JDK version (e.g. jdk21) after running the
// capture script with JDK_LABEL=<name>.
var fixtureJDKs = []string{"jdk17", "jdk8"}

func loadRMIFixture(t *testing.T, jdk, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testcases", "rmi", jdk, name))
	require.NoError(t, err)
	return data
}

func assertClientPrelude(t *testing.T, tr *Transmission) *CallMessage {
	t.Helper()
	require.NotNil(t, tr.Handshake)
	require.Equal(t, JRMI_MAGIC, tr.Handshake.Magic)
	require.Equal(t, uint16(2), tr.Handshake.Version)
	require.Equal(t, ProtocolStream, tr.Handshake.Protocol)
	require.NotNil(t, tr.ClientEndpoint)
	require.NotEmpty(t, tr.ClientEndpoint.Host)
	require.Len(t, tr.Messages, 1)
	call, ok := tr.Messages[0].(*CallMessage)
	require.True(t, ok)
	require.True(t, call.ObjID.IsRegistry(), "expected REGISTRY_ID ObjID")
	require.Equalf(t, RegistryInterfaceHash, call.MethodHash,
		"interface hash mismatch; got 0x%X — this capture's JDK may have changed the Registry stub", call.MethodHash)
	return call
}

func assertServerPrelude(t *testing.T, tr *Transmission) Message {
	t.Helper()
	require.Nil(t, tr.Handshake)
	require.NotNil(t, tr.Acknowledge)
	require.Equal(t, AckFlag, tr.Acknowledge.Flag)
	require.NotEmpty(t, tr.Acknowledge.Host)
	require.Len(t, tr.Messages, 1)
	return tr.Messages[0]
}

func forEachJDK(t *testing.T, f func(t *testing.T, jdk string)) {
	t.Helper()
	for _, jdk := range fixtureJDKs {
		jdk := jdk
		t.Run(jdk, func(t *testing.T) { f(t, jdk) })
	}
}

// ---------- client → server (call) captures ----------

func TestIntegrationLookupCall(t *testing.T) {
	forEachJDK(t, func(t *testing.T, jdk string) {
		tr, err := FromBytes(loadRMIFixture(t, jdk, "lookup-c2s.bin"))
		require.NoError(t, err)
		call := assertClientPrelude(t, tr)

		require.Equal(t, LookupOpIndex, call.Operation)
		require.NotNil(t, call.Decoded)
		require.Equal(t, "Registry.lookup", call.Decoded.Method)
		require.Len(t, call.Decoded.Args, 1)
		require.Equal(t, "ghost", call.Decoded.Args[0].Value)
	})
}

func TestIntegrationListCall(t *testing.T) {
	forEachJDK(t, func(t *testing.T, jdk string) {
		tr, err := FromBytes(loadRMIFixture(t, jdk, "list-c2s.bin"))
		require.NoError(t, err)
		call := assertClientPrelude(t, tr)

		require.Equal(t, ListOpIndex, call.Operation)
		require.NotNil(t, call.Decoded)
		require.Equal(t, "Registry.list", call.Decoded.Method)
		require.Empty(t, call.Decoded.Args)
		require.Empty(t, call.ObjectArgs)
	})
}

func TestIntegrationBindCall(t *testing.T) {
	forEachJDK(t, func(t *testing.T, jdk string) {
		tr, err := FromBytes(loadRMIFixture(t, jdk, "bind-c2s.bin"))
		require.NoError(t, err)
		call := assertClientPrelude(t, tr)

		require.Equal(t, BindOpIndex, call.Operation)
		require.NotNil(t, call.Decoded)
		require.Equal(t, "Registry.bind", call.Decoded.Method)
		require.Len(t, call.Decoded.Args, 2)
		require.Equal(t, "bind-name", call.Decoded.Args[0].Value)
		stub, ok := call.Decoded.Args[1].Value.(*serz.TCContent)
		require.True(t, ok, "bind obj arg should be *serz.TCContent")
		require.Equal(t, serz.JAVA_TC_OBJECT, stub.Flag)
		require.NotNil(t, stub.Object)
	})
}

func TestIntegrationRebindCall(t *testing.T) {
	forEachJDK(t, func(t *testing.T, jdk string) {
		tr, err := FromBytes(loadRMIFixture(t, jdk, "rebind-c2s.bin"))
		require.NoError(t, err)
		call := assertClientPrelude(t, tr)

		require.Equal(t, RebindOpIndex, call.Operation)
		require.NotNil(t, call.Decoded)
		require.Equal(t, "Registry.rebind", call.Decoded.Method)
		require.Equal(t, "rebind-name", call.Decoded.Args[0].Value)
		stub, ok := call.Decoded.Args[1].Value.(*serz.TCContent)
		require.True(t, ok)
		require.Equal(t, serz.JAVA_TC_OBJECT, stub.Flag)
	})
}

func TestIntegrationUnbindCall(t *testing.T) {
	forEachJDK(t, func(t *testing.T, jdk string) {
		tr, err := FromBytes(loadRMIFixture(t, jdk, "unbind-c2s.bin"))
		require.NoError(t, err)
		call := assertClientPrelude(t, tr)

		require.Equal(t, UnbindOpIndex, call.Operation)
		require.NotNil(t, call.Decoded)
		require.Equal(t, "Registry.unbind", call.Decoded.Method)
		require.Len(t, call.Decoded.Args, 1)
		require.Equal(t, "ghost", call.Decoded.Args[0].Value)
	})
}

// ---------- server → client (return) captures ----------

func TestIntegrationLookupReturn_Exception(t *testing.T) {
	forEachJDK(t, func(t *testing.T, jdk string) {
		tr, err := FromBytes(loadRMIFixture(t, jdk, "lookup-s2c.bin"))
		require.NoError(t, err)
		msg := assertServerPrelude(t, tr)
		ret, ok := msg.(*ReturnMessage)
		require.True(t, ok)
		require.Equal(t, ExceptionalReturn, ret.ReturnType)
		require.NotNil(t, ret.Payload)
		require.Equal(t, serz.JAVA_TC_OBJECT, ret.Payload.Flag, "expected serialized Throwable")
	})
}

func TestIntegrationListReturn_Normal(t *testing.T) {
	forEachJDK(t, func(t *testing.T, jdk string) {
		tr, err := FromBytes(loadRMIFixture(t, jdk, "list-s2c.bin"))
		require.NoError(t, err)
		msg := assertServerPrelude(t, tr)
		ret, ok := msg.(*ReturnMessage)
		require.True(t, ok)
		require.Equal(t, NormalReturn, ret.ReturnType)
		require.NotNil(t, ret.Payload)
		require.Equal(t, serz.JAVA_TC_ARRAY, ret.Payload.Flag, "expected String[] return")
	})
}

func TestIntegrationBindReturn_Void(t *testing.T) {
	forEachJDK(t, func(t *testing.T, jdk string) {
		tr, err := FromBytes(loadRMIFixture(t, jdk, "bind-s2c.bin"))
		require.NoError(t, err)
		msg := assertServerPrelude(t, tr)
		ret, ok := msg.(*ReturnMessage)
		require.True(t, ok)
		require.Equal(t, NormalReturn, ret.ReturnType)
		require.Nil(t, ret.Payload, "void return should have no payload")
	})
}

func TestIntegrationRebindReturn_Void(t *testing.T) {
	forEachJDK(t, func(t *testing.T, jdk string) {
		tr, err := FromBytes(loadRMIFixture(t, jdk, "rebind-s2c.bin"))
		require.NoError(t, err)
		msg := assertServerPrelude(t, tr)
		ret, ok := msg.(*ReturnMessage)
		require.True(t, ok)
		require.Equal(t, NormalReturn, ret.ReturnType)
		require.Nil(t, ret.Payload)
	})
}

func TestIntegrationUnbindReturn_Exception(t *testing.T) {
	forEachJDK(t, func(t *testing.T, jdk string) {
		tr, err := FromBytes(loadRMIFixture(t, jdk, "unbind-s2c.bin"))
		require.NoError(t, err)
		msg := assertServerPrelude(t, tr)
		ret, ok := msg.(*ReturnMessage)
		require.True(t, ok)
		require.Equal(t, ExceptionalReturn, ret.ReturnType)
		require.NotNil(t, ret.Payload)
		require.Equal(t, serz.JAVA_TC_OBJECT, ret.Payload.Flag)
	})
}

// ---------- ToString smoke across both JDKs ----------

func TestIntegrationLookupToString(t *testing.T) {
	forEachJDK(t, func(t *testing.T, jdk string) {
		tr, err := FromBytes(loadRMIFixture(t, jdk, "lookup-c2s.bin"))
		require.NoError(t, err)
		s := tr.ToString()
		// Compact @Decoded summary at the top.
		require.Contains(t, s, "JRMP Transmission")
		require.Contains(t, s, "@Method - Registry.lookup")
		require.Contains(t, s, `[0] name (String) = "ghost"`)
		// Dissector-style @Serialization with inline annotations on each node.
		require.Contains(t, s, "@Serialization")
		require.Contains(t, s, "TC_BLOCKDATA - 0x77  (Call primitives: ObjID + op + methodHash)")
		require.Contains(t, s, "@Length - 34 - 0x22")
		require.Contains(t, s, `TC_STRING - 0x74  (Registry.lookup arg 0: "name")`)
		// The leading-block decomposition must carry both decimal *and* hex
		// for every primitive field — those bytes are not echoed anywhere
		// else now, so losing the hex here would hide them entirely.
		require.Contains(t, s, "@ObjNum - 0 (REGISTRY_ID) - 0x00 00 00 00 00 00 00 00")
		require.Contains(t, s, "@Unique - 0 - 0x00 00 00 00")
		require.Contains(t, s, "@Time - 0 - 0x00 00 00 00 00 00 00 00")
		require.Contains(t, s, "@Count - 0 - 0x00 00")
		require.Contains(t, s, "@Operation - 2 - 0x00 00 00 02")
		require.Contains(t, s, "@MethodHash - 4905912898345647071 - 0x44 15 4d c9 d4 e6 3b df")
		// JRMP framing fields outside @Serialization keep their hex too.
		require.Contains(t, s, "@Port - 0 - 0x")
		require.Regexp(t, `@Length - \d+ - 0x`, s)
		// Ordering invariant: @Decoded summary first, embedded stream second;
		// the leading TC_BLOCKDATA must precede any TC_STRING so the logical
		// header → args flow stays obvious.
		require.Less(t, indexOf(s, "@Method - Registry.lookup"), indexOf(s, "@Serialization"))
		require.Less(t, indexOf(s, "TC_BLOCKDATA"), indexOf(s, "TC_STRING"))
	})
}

// TestIntegrationBindToStringShowsStub locks in that the bind call's stub
// (a TC_OBJECT with a TC_PROXYCLASSDESC) is rendered under @Serialization
// with an inline semantic label, and that the @Decoded summary references
// it by handler instead of dumping the subtree a second time.
func TestIntegrationBindToStringShowsStub(t *testing.T) {
	forEachJDK(t, func(t *testing.T, jdk string) {
		tr, err := FromBytes(loadRMIFixture(t, jdk, "bind-c2s.bin"))
		require.NoError(t, err)
		s := tr.ToString()
		require.Contains(t, s, "@Method - Registry.bind")
		require.Contains(t, s, `[0] name (String) = "bind-name"`)
		require.Regexp(t, `\[1\] obj \(Remote\) — TC_OBJECT handler \d+ — see @Contents`, s)
		require.Contains(t, s, `TC_OBJECT - 0x73  (Registry.bind arg 1: "obj")`)
		require.Contains(t, s, "TC_PROXYCLASSDESC")
		require.Contains(t, s, "java.rmi.Remote")
		require.Contains(t, s, "java.lang.reflect.Proxy")
		// No-duplication guard: TC_PROXYCLASSDESC must appear exactly once.
		// The old layout rendered it twice (once in @Serialization, once in
		// @Decoded.Args), which was the point of this refactor.
		require.Equal(t, 1, strings.Count(s, "TC_PROXYCLASSDESC"),
			"TC_PROXYCLASSDESC should appear exactly once — the stub tree must not be duplicated between @Serialization and @Decoded")
	})
}

// TestIntegrationExceptionReturnToStringShowsThrowable does the same regression
// lock for the server-side exceptional return (NotBoundException).
func TestIntegrationExceptionReturnToStringShowsThrowable(t *testing.T) {
	forEachJDK(t, func(t *testing.T, jdk string) {
		tr, err := FromBytes(loadRMIFixture(t, jdk, "lookup-s2c.bin"))
		require.NoError(t, err)
		s := tr.ToString()
		require.Contains(t, s, "ReturnData")
		require.Contains(t, s, "ExceptionalReturn")
		require.Contains(t, s, "@Serialization")
		require.Contains(t, s, "TC_OBJECT")
		require.Contains(t, s, "java.rmi.NotBoundException")
	})
}
