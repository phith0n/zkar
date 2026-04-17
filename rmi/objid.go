package rmi

import (
	"encoding/binary"
	"fmt"

	"github.com/phith0n/zkar/commons"
)

// UID mirrors java.rmi.server.UID: 4-byte Unique + 8-byte Time + 2-byte Count = 14 bytes.
type UID struct {
	Unique int32
	Time   int64
	Count  int16
}

// ObjID mirrors java.rmi.server.ObjID: 8-byte ObjNum + 14-byte UID = 22 bytes.
type ObjID struct {
	ObjNum int64
	UID    UID
}

func parseUID(bs []byte) (UID, error) {
	if len(bs) != uidLen {
		return UID{}, fmt.Errorf("UID expects %d bytes, got %d", uidLen, len(bs))
	}
	return UID{
		Unique: int32(binary.BigEndian.Uint32(bs[0:4])),
		Time:   int64(binary.BigEndian.Uint64(bs[4:12])),
		Count:  int16(binary.BigEndian.Uint16(bs[12:14])),
	}, nil
}

func parseObjID(bs []byte) (ObjID, error) {
	if len(bs) != objIDLen {
		return ObjID{}, fmt.Errorf("ObjID expects %d bytes, got %d", objIDLen, len(bs))
	}
	uid, err := parseUID(bs[8:22])
	if err != nil {
		return ObjID{}, err
	}
	return ObjID{
		ObjNum: int64(binary.BigEndian.Uint64(bs[0:8])),
		UID:    uid,
	}, nil
}

func (u UID) IsZero() bool {
	return u.Unique == 0 && u.Time == 0 && u.Count == 0
}

// ToString intentionally omits the raw hex for each field: UID appears
// decomposed out of a TC_BLOCKDATA whose bytes are already printed verbatim
// under @Serialization, so echoing the hex here would just duplicate them.
func (u UID) ToString() string {
	b := commons.NewPrinter()
	b.Printf("UID")
	b.IncreaseIndent()
	b.Printf("@Unique - %d", u.Unique)
	b.Printf("@Time - %d", u.Time)
	b.Printf("@Count - %d", u.Count)
	return b.String()
}

// IsRegistry reports whether this ObjID is the well-known java.rmi.registry.Registry identifier.
func (o ObjID) IsRegistry() bool {
	return o.ObjNum == RegistryObjNum && o.UID.IsZero()
}

// ToString mirrors UID's no-hex convention: the underlying bytes are already
// in the @Serialization's TC_BLOCKDATA dump.
func (o ObjID) ToString() string {
	b := commons.NewPrinter()
	b.Printf("ObjID")
	b.IncreaseIndent()
	if o.IsRegistry() {
		b.Printf("@ObjNum - %d (REGISTRY_ID)", o.ObjNum)
	} else {
		b.Printf("@ObjNum - %d", o.ObjNum)
	}
	b.Print(o.UID.ToString())
	return b.String()
}
