package serz

import (
	"fmt"
)

type TCClassPointer struct {
	Flag            byte
	NormalClassDesc *TCClassDesc
	ProxyClassDesc  *TCProxyClassDesc
	Null            *TCNull
	Reference       *TCReference
}

func (cp *TCClassPointer) ToBytes() []byte {
	var result []byte
	switch cp.Flag {
	case JAVA_TC_NULL:
		result = cp.Null.ToBytes()
	case JAVA_TC_REFERENCE:
		result = cp.Reference.ToBytes()
	case JAVA_TC_CLASSDESC:
		result = cp.NormalClassDesc.ToBytes()
	case JAVA_TC_PROXYCLASSDESC:
		result = cp.ProxyClassDesc.ToBytes()
	default:
		panic("unexpected TCClassPointer Flag")
	}

	return result
}

func (cp *TCClassPointer) ToString() string {
	var result string
	switch cp.Flag {
	case JAVA_TC_NULL:
		result = cp.Null.ToString()
	case JAVA_TC_REFERENCE:
		result = cp.Reference.ToString()
	case JAVA_TC_CLASSDESC:
		result = cp.NormalClassDesc.ToString()
	case JAVA_TC_PROXYCLASSDESC:
		result = cp.ProxyClassDesc.ToString()
	default:
		panic("unexpected TCClassPointer Flag")
	}

	return result
}

func (cp *TCClassPointer) FindClassBag(stream *ObjectStream) (*ClassBag, error) {
	var normalClassDesc *TCClassDesc
	var proxyClassDesc *TCProxyClassDesc
	var err error
	if cp.Flag == JAVA_TC_NULL {
		return nil, nil
	} else if cp.Flag == JAVA_TC_PROXYCLASSDESC {
		proxyClassDesc = cp.ProxyClassDesc
	} else if cp.Flag == JAVA_TC_CLASSDESC {
		normalClassDesc = cp.NormalClassDesc
	} else {
		if cp.Reference.Flag == JAVA_TC_CLASSDESC {
			normalClassDesc = cp.Reference.NormalClassDesc
		} else if cp.Reference.Flag == JAVA_TC_PROXYCLASSDESC {
			proxyClassDesc = cp.Reference.ProxyClassDesc
		} else {
			return nil, fmt.Errorf("reference must be a JAVA_TC_CLASSDESC or JAVA_TC_PROXYCLASSDESC")
		}
	}

	var super *TCClassPointer
	var bag = new(ClassBag)
	if normalClassDesc != nil {
		bag.Add(normalClassDesc)
		super = normalClassDesc.SuperClassPointer
	} else {
		super = proxyClassDesc.SuperClassPointer
	}

	newBag, err := super.FindClassBag(stream)
	if err != nil {
		return nil, err
	}

	if newBag != nil {
		bag.Merge(newBag)
	}

	return bag, nil
}

func readTCClassPointer(stream *ObjectStream) (*TCClassPointer, error) {
	// read JAVA_TC_CLASSDESC Flag
	flag, _ := stream.PeekN(1)
	if flag[0] == JAVA_TC_NULL {
		return &TCClassPointer{
			Flag: JAVA_TC_NULL,
			Null: readTCNull(stream),
		}, nil
	} else if flag[0] == JAVA_TC_REFERENCE {
		reference, err := readTCReference(stream)
		if err != nil {
			return nil, err
		}

		return &TCClassPointer{
			Flag:      JAVA_TC_REFERENCE,
			Reference: reference,
		}, nil
	} else if flag[0] == JAVA_TC_CLASSDESC {
		desc, err := readTCNormalClassDesc(stream)
		if err != nil {
			return nil, err
		}

		return &TCClassPointer{
			Flag:            JAVA_TC_CLASSDESC,
			NormalClassDesc: desc,
		}, nil
	} else if flag[0] == JAVA_TC_PROXYCLASSDESC {
		desc, err := readTCProxyClassDesc(stream)
		if err != nil {
			return nil, err
		}

		return &TCClassPointer{
			Flag:           JAVA_TC_PROXYCLASSDESC,
			ProxyClassDesc: desc,
		}, nil
	} else {
		return nil, fmt.Errorf("read ClassDesc failed in index %v", stream.CurrentIndex())
	}
}
