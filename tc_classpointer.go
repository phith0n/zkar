package javaserialize

import (
	"fmt"
)

type TCClassPointer struct {
	Flag byte
	ClassDesc *TCClassDesc
	Null *TCNull
	Reference *TCReference
}

func (cp *TCClassPointer) ToBytes() []byte {
	var result []byte
	switch cp.Flag {
	case JAVA_TC_NULL:
		result = cp.Null.ToBytes()
	case JAVA_TC_REFERENCE:
		result = cp.Reference.ToBytes()
	case JAVA_TC_CLASSDESC, JAVA_TC_PROXYCLASSDESC:
		result = cp.ClassDesc.ToBytes()
	}

	return result
}

func (cp *TCClassPointer) FindClassBag(stream *ObjectStream) (*ClassBag, error) {
	var normalClassDesc *TCNormalClassDesc
	var proxyClassDesc *TCProxyClassDesc
	var err error
	if cp.Flag == JAVA_TC_NULL {
		return nil, nil
	} else if cp.Flag == JAVA_TC_PROXYCLASSDESC {
		proxyClassDesc = cp.ClassDesc.ProxyClassDesc
	} else if cp.Flag == JAVA_TC_CLASSDESC {
		normalClassDesc = cp.ClassDesc.NormalClassDesc
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
			Flag: JAVA_TC_REFERENCE,
			Reference: reference,
		}, nil
	} else if flag[0] == JAVA_TC_CLASSDESC || flag[0] == JAVA_TC_PROXYCLASSDESC {
		desc, err := readTCClassDesc(stream)
		if err != nil {
			return nil, err
		}

		return &TCClassPointer{
			Flag:      flag[0],
			ClassDesc: desc,
		}, nil
	} else {
		return nil, fmt.Errorf("read ClassDesc failed in index %v", stream.CurrentIndex())
	}
}
