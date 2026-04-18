package rmi

// JRMI_MAGIC is the four-byte "JRMI" header that prefixes every JRMP connection.
var JRMI_MAGIC = []byte{0x4A, 0x52, 0x4D, 0x49}

// JRMP sub-protocol flags, written immediately after the magic+version.
const (
	ProtocolStream    byte = 0x4B
	ProtocolSingleOp  byte = 0x4C
	ProtocolMultiplex byte = 0x4D
)

// Server-to-client handshake response flag.
const AckFlag byte = 0x4E

// JRMP message opcodes (appear as the first byte of each message after the handshake).
const (
	MsgCall       byte = 0x50
	MsgReturnData byte = 0x51
	MsgPing       byte = 0x52
	MsgPingAck    byte = 0x53
	MsgDgcAck     byte = 0x54
)

// ReturnData payload types, written as the first byte inside the Return message's embedded serialization stream.
const (
	NormalReturn      byte = 0x01
	ExceptionalReturn byte = 0x02
)

// RegistryObjNum is the well-known ObjNum for java.rmi.registry.Registry.
// Combined with a zero UID it forms ObjID.REGISTRY_ID.
const RegistryObjNum int64 = 0

// Registry dispatch on the wire.
//
// java.rmi.registry.Registry has a pre-compiled stub (sun.rmi.registry.RegistryImpl_Stub),
// so its RMI calls use the legacy "operation index + interface hash" form:
//   - int32 operation: 0-4, indexing into the stub's fixed method table below
//   - int64 hash:      the Registry interface hash (identical for all five methods)
//
// Modern JRMP's "operation = -1 + per-method hash" form applies only to
// dynamic-proxy stubs; the Registry itself does not use it.
const (
	BindOpIndex   int32 = 0
	ListOpIndex   int32 = 1
	LookupOpIndex int32 = 2
	RebindOpIndex int32 = 3
	UnbindOpIndex int32 = 4
)

// RegistryInterfaceHash is sent as the methodHash field of every
// RegistryImpl_Stub call. Calibrated against a live rmiregistry capture on
// Zulu OpenJDK 17.0.14; known to match upstream OpenJDK 17.
// If a future JDK changes the interface signature and regenerates the stub,
// this value must be recalibrated from a capture.
const RegistryInterfaceHash int64 = 0x44154DC9D4E63BDF

// Fixed primitive-payload sizes in embedded Call/Return serialization streams.
const (
	callPrimitiveLen   = 34 // ObjID(22) + op(4) + hash(8)
	returnPrimitiveLen = 15 // returnType(1) + UID(14)
	objIDLen           = 22
	uidLen             = 14
)
