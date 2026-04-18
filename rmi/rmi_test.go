package rmi

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/phith0n/zkar/serz"
	"github.com/stretchr/testify/require"
)

// ---------- fixture builders ----------
//
// These produce the exact byte layouts of JRMP frames. The parser is
// adversarial against its own builders: we construct bytes from scratch
// (not via a Go JRMP client) so a bug in one direction can't hide a
// symmetric bug in the other.

func buildHandshake() []byte {
	var buf bytes.Buffer
	buf.Write(JRMI_MAGIC)
	_ = binary.Write(&buf, binary.BigEndian, uint16(2))
	buf.WriteByte(ProtocolStream)
	return buf.Bytes()
}

func buildClientEndpointEcho(host string, port int32) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint16(len(host)))
	buf.WriteString(host)
	_ = binary.Write(&buf, binary.BigEndian, port)
	return buf.Bytes()
}

func buildAck(host string, port int32) []byte {
	var buf bytes.Buffer
	buf.WriteByte(AckFlag)
	_ = binary.Write(&buf, binary.BigEndian, uint16(len(host)))
	buf.WriteString(host)
	_ = binary.Write(&buf, binary.BigEndian, port)
	return buf.Bytes()
}

func buildPing() []byte    { return []byte{MsgPing} }
func buildPingAck() []byte { return []byte{MsgPingAck} }

func buildUIDBytes(u UID) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, u.Unique)
	_ = binary.Write(&buf, binary.BigEndian, u.Time)
	_ = binary.Write(&buf, binary.BigEndian, u.Count)
	return buf.Bytes()
}

func buildDgcAck(u UID) []byte {
	var buf bytes.Buffer
	buf.WriteByte(MsgDgcAck)
	buf.Write(buildUIDBytes(u))
	return buf.Bytes()
}

func buildObjIDBytes(id ObjID) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, id.ObjNum)
	buf.Write(buildUIDBytes(id.UID))
	return buf.Bytes()
}

func buildTCString(s string) []byte {
	var buf bytes.Buffer
	buf.WriteByte(serz.JAVA_TC_STRING)
	_ = binary.Write(&buf, binary.BigEndian, uint16(len(s)))
	buf.WriteString(s)
	return buf.Bytes()
}

func buildTCNull() []byte { return []byte{serz.JAVA_TC_NULL} }

func buildCall(objID ObjID, op int32, methodHash int64, objArgs ...[]byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(MsgCall)
	buf.Write(serz.JAVA_STREAM_MAGIC)
	buf.Write(serz.JAVA_STREAM_VERSION)

	// TC_BLOCKDATA carrying ObjID(22) + op(4) + hash(8) = 34 bytes.
	buf.WriteByte(serz.JAVA_TC_BLOCKDATA)
	buf.WriteByte(callPrimitiveLen)
	buf.Write(buildObjIDBytes(objID))
	_ = binary.Write(&buf, binary.BigEndian, op)
	_ = binary.Write(&buf, binary.BigEndian, methodHash)

	for _, a := range objArgs {
		buf.Write(a)
	}
	return buf.Bytes()
}

func buildReturn(returnType byte, ackUID UID, payload []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(MsgReturnData)
	buf.Write(serz.JAVA_STREAM_MAGIC)
	buf.Write(serz.JAVA_STREAM_VERSION)

	// TC_BLOCKDATA carrying returnType(1) + UID(14) = 15 bytes.
	buf.WriteByte(serz.JAVA_TC_BLOCKDATA)
	buf.WriteByte(returnPrimitiveLen)
	buf.WriteByte(returnType)
	buf.Write(buildUIDBytes(ackUID))

	if payload != nil {
		buf.Write(payload)
	}
	return buf.Bytes()
}

// ---------- handshake / acknowledge ----------

func TestHandshakeClientToServer(t *testing.T) {
	tr, err := FromBytes(buildHandshake())
	require.NoError(t, err)
	require.NotNil(t, tr.Handshake)
	require.Equal(t, JRMI_MAGIC, tr.Handshake.Magic)
	require.Equal(t, uint16(2), tr.Handshake.Version)
	require.Equal(t, ProtocolStream, tr.Handshake.Protocol)
	require.Nil(t, tr.Acknowledge)
	require.Empty(t, tr.Messages)
}

func TestHandshakeBadMagic(t *testing.T) {
	// First byte 0x4A triggers the handshake path; bytes 2-4 mismatch,
	// so readHandshake's magic check fires with a specific error.
	bad := []byte{0x4A, 0xDE, 0xAD, 0xBE, 0x00, 0x02, 0x4B}
	_, err := FromBytes(bad)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid JRMI magic")
}

func TestHandshakeUnsupportedProtocol(t *testing.T) {
	bad := append([]byte{}, buildHandshake()...)
	bad[6] = ProtocolSingleOp
	_, err := FromBytes(bad)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported JRMP sub-protocol")
}

func TestAcknowledge(t *testing.T) {
	tr, err := FromBytes(buildAck("localhost", 12345))
	require.NoError(t, err)
	require.Nil(t, tr.Handshake)
	require.NotNil(t, tr.Acknowledge)
	require.Equal(t, AckFlag, tr.Acknowledge.Flag)
	require.Equal(t, "localhost", tr.Acknowledge.Host)
	require.Equal(t, int32(12345), tr.Acknowledge.Port)
}

// ---------- ping / pingack / dgcack ----------

func TestPing(t *testing.T) {
	tr, err := FromBytes(buildPing())
	require.NoError(t, err)
	require.Len(t, tr.Messages, 1)
	_, ok := tr.Messages[0].(*PingMessage)
	require.True(t, ok)
	require.Equal(t, MsgPing, tr.Messages[0].Op())
}

func TestPingAck(t *testing.T) {
	tr, err := FromBytes(buildPingAck())
	require.NoError(t, err)
	require.Len(t, tr.Messages, 1)
	_, ok := tr.Messages[0].(*PingAckMessage)
	require.True(t, ok)
}

func TestDgcAck(t *testing.T) {
	uid := UID{Unique: 42, Time: 1700000000, Count: 7}
	tr, err := FromBytes(buildDgcAck(uid))
	require.NoError(t, err)
	require.Len(t, tr.Messages, 1)
	m, ok := tr.Messages[0].(*DgcAckMessage)
	require.True(t, ok)
	require.Equal(t, uid, m.UID)
}

// ---------- call / registry decoding ----------

// registryCallFrame wraps the three-part prelude (handshake + echo + call)
// that a real client would send, so the full stream exercises every top-level
// parser path.
func registryCallFrame(op int32, args ...[]byte) []byte {
	var buf bytes.Buffer
	buf.Write(buildHandshake())
	buf.Write(buildClientEndpointEcho("myhost", 4444))
	buf.Write(buildCall(ObjID{}, op, RegistryInterfaceHash, args...))
	return buf.Bytes()
}

func TestParseLookup(t *testing.T) {
	tr, err := FromBytes(registryCallFrame(LookupOpIndex, buildTCString("foo")))
	require.NoError(t, err)

	require.NotNil(t, tr.Handshake)
	require.NotNil(t, tr.ClientEndpoint)
	require.Equal(t, "myhost", tr.ClientEndpoint.Host)
	require.Equal(t, int32(4444), tr.ClientEndpoint.Port)

	require.Len(t, tr.Messages, 1)
	call, ok := tr.Messages[0].(*CallMessage)
	require.True(t, ok)
	require.True(t, call.ObjID.IsRegistry())
	require.Equal(t, LookupOpIndex, call.Operation)
	require.Equal(t, RegistryInterfaceHash, call.MethodHash)
	require.NotNil(t, call.Decoded)
	require.Equal(t, "Registry.lookup", call.Decoded.Method)
	require.Len(t, call.Decoded.Args, 1)
	require.Equal(t, "name", call.Decoded.Args[0].Name)
	require.Equal(t, "foo", call.Decoded.Args[0].Value)

	// Smoke-test the ToString rendering so we catch nil-deref / indent regressions.
	s := tr.ToString()
	require.Contains(t, s, "Registry.lookup")
	require.Contains(t, s, `"foo"`)
	require.Contains(t, s, "REGISTRY_ID")
}

func TestParseUnbind(t *testing.T) {
	tr, err := FromBytes(registryCallFrame(UnbindOpIndex, buildTCString("bar")))
	require.NoError(t, err)
	call := tr.Messages[0].(*CallMessage)
	require.Equal(t, "Registry.unbind", call.Decoded.Method)
	require.Equal(t, "bar", call.Decoded.Args[0].Value)
}

func TestParseBind(t *testing.T) {
	tr, err := FromBytes(registryCallFrame(BindOpIndex, buildTCString("svc"), buildTCNull()))
	require.NoError(t, err)
	call := tr.Messages[0].(*CallMessage)
	require.Equal(t, "Registry.bind", call.Decoded.Method)
	require.Len(t, call.Decoded.Args, 2)
	require.Equal(t, "svc", call.Decoded.Args[0].Value)
	// Remote arg is preserved as the raw TCContent so users can drill in.
	c, ok := call.Decoded.Args[1].Value.(*serz.TCContent)
	require.True(t, ok)
	require.Equal(t, serz.JAVA_TC_NULL, c.Flag)
}

func TestParseRebind(t *testing.T) {
	tr, err := FromBytes(registryCallFrame(RebindOpIndex, buildTCString("svc2"), buildTCNull()))
	require.NoError(t, err)
	call := tr.Messages[0].(*CallMessage)
	require.Equal(t, "Registry.rebind", call.Decoded.Method)
	require.Equal(t, "svc2", call.Decoded.Args[0].Value)
}

func TestParseList(t *testing.T) {
	tr, err := FromBytes(registryCallFrame(ListOpIndex))
	require.NoError(t, err)
	call := tr.Messages[0].(*CallMessage)
	require.Equal(t, "Registry.list", call.Decoded.Method)
	require.Empty(t, call.Decoded.Args)
}

// TestCallRejectsNonRegistry covers every way a Call's header can fail the
// Registry dispatch gate: non-zero ObjNum, wrong interface hash, unknown
// op-index. Each branch must error at parse time with a message that
// identifies the specific mismatch.
func TestCallRejectsNonRegistry(t *testing.T) {
	cases := []struct {
		name    string
		objID   ObjID
		op      int32
		hash    int64
		errFrag string
	}{
		{
			name:    "non_registry_objid",
			objID:   ObjID{ObjNum: 99, UID: UID{Unique: 1, Time: 2, Count: 3}},
			op:      LookupOpIndex,
			hash:    RegistryInterfaceHash,
			errFrag: "ObjID.ObjNum=99",
		},
		{
			name:    "wrong_interface_hash",
			objID:   ObjID{}, // REGISTRY_ID
			op:      LookupOpIndex,
			hash:    0x1234567890ABCDEF,
			errFrag: "methodHash=0x1234567890ABCDEF",
		},
		{
			name:    "unknown_op_index",
			objID:   ObjID{},
			op:      99,
			hash:    RegistryInterfaceHash,
			errFrag: "unknown Registry op-index 99",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			data := buildCall(tc.objID, tc.op, tc.hash, buildTCString("x"))
			_, err := FromBytes(data)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.errFrag)
		})
	}
}

// ---------- return ----------

func TestNormalReturnWithPayload(t *testing.T) {
	uid := UID{Unique: 10, Time: 20, Count: 30}
	tr, err := FromBytes(buildReturn(NormalReturn, uid, buildTCString("result")))
	require.NoError(t, err)
	ret, ok := tr.Messages[0].(*ReturnMessage)
	require.True(t, ok)
	require.Equal(t, NormalReturn, ret.ReturnType)
	require.Equal(t, uid, ret.AckUID)
	require.NotNil(t, ret.Payload)
	require.Equal(t, serz.JAVA_TC_STRING, ret.Payload.Flag)
}

func TestVoidReturn(t *testing.T) {
	uid := UID{Unique: 1, Time: 2, Count: 3}
	tr, err := FromBytes(buildReturn(NormalReturn, uid, nil))
	require.NoError(t, err)
	ret := tr.Messages[0].(*ReturnMessage)
	require.Nil(t, ret.Payload)
}

func TestExceptionalReturn(t *testing.T) {
	uid := UID{Unique: 99, Time: 100, Count: 1}
	// TC_NULL stands in for the Throwable so the fixture stays hand-crafted;
	// real streams would have a TC_OBJECT, but that path is already covered
	// by the TCContent dispatcher in serz.
	tr, err := FromBytes(buildReturn(ExceptionalReturn, uid, buildTCNull()))
	require.NoError(t, err)
	ret := tr.Messages[0].(*ReturnMessage)
	require.Equal(t, ExceptionalReturn, ret.ReturnType)
	require.NotNil(t, ret.Payload)
	require.Equal(t, serz.JAVA_TC_NULL, ret.Payload.Flag)
}

// ---------- direction-agnostic / sequencing / empty ----------

func TestDirectionAgnosticPureMessages(t *testing.T) {
	// Bytes starting with a JRMP message flag, no handshake or ack — mimics
	// resuming parse mid-stream.
	tr, err := FromBytes(buildPing())
	require.NoError(t, err)
	require.Nil(t, tr.Handshake)
	require.Nil(t, tr.Acknowledge)
	require.Len(t, tr.Messages, 1)
}

func TestMessageSequence(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(buildHandshake())
	buf.Write(buildClientEndpointEcho("h", 1))
	buf.Write(buildCall(ObjID{}, LookupOpIndex, RegistryInterfaceHash, buildTCString("a")))
	buf.Write(buildPing())
	buf.Write(buildCall(ObjID{}, UnbindOpIndex, RegistryInterfaceHash, buildTCString("b")))
	buf.Write(buildDgcAck(UID{Unique: 1, Time: 2, Count: 3}))

	tr, err := FromBytes(buf.Bytes())
	require.NoError(t, err)
	require.Len(t, tr.Messages, 4)
	require.Equal(t, MsgCall, tr.Messages[0].Op())
	require.Equal(t, MsgPing, tr.Messages[1].Op())
	require.Equal(t, MsgCall, tr.Messages[2].Op())
	require.Equal(t, MsgDgcAck, tr.Messages[3].Op())

	// The two calls must round-trip to Registry.lookup and Registry.unbind
	// respectively — regression guard against frame-boundary bleeding.
	require.Equal(t, "Registry.lookup", tr.Messages[0].(*CallMessage).Decoded.Method)
	require.Equal(t, "Registry.unbind", tr.Messages[2].(*CallMessage).Decoded.Method)
}

// TestBackToBackRegistryCallsNoSeparator is a regression guard: a Registry
// Call uses exact-count reading, so after its last arg the parser must NOT
// peek at the next byte. If it did, two Calls concatenated without any
// intervening frame would read through frame 1's last arg into frame 2's
// flag byte (0x50) and mis-parse. With exact count both Calls parse
// cleanly.
func TestBackToBackRegistryCallsNoSeparator(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(buildHandshake())
	buf.Write(buildClientEndpointEcho("h", 1))
	buf.Write(buildCall(ObjID{}, LookupOpIndex, RegistryInterfaceHash, buildTCString("first")))
	buf.Write(buildCall(ObjID{}, UnbindOpIndex, RegistryInterfaceHash, buildTCString("second")))

	tr, err := FromBytes(buf.Bytes())
	require.NoError(t, err)
	require.Len(t, tr.Messages, 2)
	require.Equal(t, "Registry.lookup", tr.Messages[0].(*CallMessage).Decoded.Method)
	require.Equal(t, "first", tr.Messages[0].(*CallMessage).Decoded.Args[0].Value)
	require.Equal(t, "Registry.unbind", tr.Messages[1].(*CallMessage).Decoded.Method)
	require.Equal(t, "second", tr.Messages[1].(*CallMessage).Decoded.Args[0].Value)
}

func TestEmptyInput(t *testing.T) {
	tr, err := FromBytes(nil)
	require.NoError(t, err)
	require.NotNil(t, tr)
	require.Nil(t, tr.Handshake)
	require.Empty(t, tr.Messages)
}

func TestUnknownMessageFlag(t *testing.T) {
	_, err := FromBytes([]byte{0x66})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown JRMP message flag")
}
