package javaserialize

// JAVA_STREAM_MAGIC Magic Number
var JAVA_STREAM_MAGIC = []byte {0xAC, 0xED}

// JAVA_STREAM_VERSION Version number that is written to the stream header.
var JAVA_STREAM_VERSION = []byte {0x00, 0x05}

// =============== TC_* ===============

// JAVA_TC_BASE First tag value.
var JAVA_TC_BASE byte = 0x70

// JAVA_TC_NULL Null object reference.
var JAVA_TC_NULL byte = 0x70

// JAVA_TC_REFERENCE Reference to an object already written into the stream.
var JAVA_TC_REFERENCE byte = 0x71

// JAVA_TC_CLASSDESC new Class Descriptor.
var JAVA_TC_CLASSDESC byte = 0x72

// JAVA_TC_OBJECT new Object.
var JAVA_TC_OBJECT byte = 0x73

// JAVA_TC_STRING new String.
var JAVA_TC_STRING byte = 0x74

// JAVA_TC_ARRAY new Array.
var JAVA_TC_ARRAY byte = 0x75

// JAVA_TC_CLASS Reference to Class.
var JAVA_TC_CLASS byte = 0x76

// JAVA_TC_BLOCKDATA Block of optional data. Byte following tag indicates number of bytes in this block data.
var JAVA_TC_BLOCKDATA byte = 0x77

// JAVA_TC_ENDBLOCKDATA End of optional block data blocks for an object.
var JAVA_TC_ENDBLOCKDATA byte = 0x78

// JAVA_TC_RESET Reset stream context. All handles written into stream are reset.
var JAVA_TC_RESET byte = 0x79

// JAVA_TC_BLOCKDATALONG long Block data. The long following the tag indicates the number of bytes in this block data.
var JAVA_TC_BLOCKDATALONG byte = 0x7A

// JAVA_TC_EXCEPTION Exception during write.
var JAVA_TC_EXCEPTION byte = 0x7B

// TC_LONGSTRING Long string.
var JAVA_TC_LONGSTRING byte = 0x7C

// TC_PROXYCLASSDESC new Proxy Class Descriptor.
var JAVA_TC_PROXYCLASSDESC byte = 0x7D

// JAVA_TC_ENUM new Enum constant.
var JAVA_TC_ENUM byte = 0x7E

// JAVA_TC_MAX Last tag value.
var JAVA_TC_MAX byte = 0x7F

// JAVA_BASE_WRITE_HANDLE First wire handle to be assigned.
var JAVA_BASE_WRITE_HANDLE int = 0x7e0000

// =============== Bit Mask ===============

// JAVA_SC_WRITE_METHOD Bit mask for ObjectStreamClass flag.
// Indicates a Serializable class defines its own writeObject method.
var JAVA_SC_WRITE_METHOD byte = 0x01

// JAVA_SC_BLOCK_DATA Bit mask for ObjectStreamClass flag.
// Indicates Externalizable data written in Block Data mode. Added for PROTOCOL_VERSION_2.
var JAVA_SC_BLOCK_DATA byte = 0x08

// JAVA_SC_SERIALIZABLE Bit mask for ObjectStreamClass flag. Indicates class is Serializable.
var JAVA_SC_SERIALIZABLE byte = 0x02

// JAVA_SC_EXTERNALIZABLE Bit mask for ObjectStreamClass flag. Indicates class is Externalizable.
var JAVA_SC_EXTERNALIZABLE byte = 0x04

// JAVA_SC_ENUM Bit mask for ObjectStreamClass flag. Indicates class is an enum type.
var JAVA_SC_ENUM byte = 0x10

// Base handler
var JAVA_BASE_HANDLER = 0x7e0000
