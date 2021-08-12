package javaserialize

import "fmt"

type TCClassDesc struct {
	IsProxyClass bool
	NormalClassDesc *TCNormalClassDesc
	ProxyClassDesc *TCProxyClassDesc
}

func (d *TCClassDesc) ToBytes() []byte {
	if d.IsProxyClass {
		return d.ProxyClassDesc.ToBytes()
	} else {
		return d.NormalClassDesc.ToBytes()
	}
}

func readTCClassDesc(stream *ObjectStream) (*TCClassDesc, error) {
	var classDesc = new(TCClassDesc)
	var err error
	flag, _ := stream.PeekN(1)
	if flag[0] == JAVA_TC_CLASSDESC {
		classDesc.IsProxyClass = false
		classDesc.NormalClassDesc, err = readTCNormalClassDesc(stream)
	} else if flag[0] == JAVA_TC_PROXYCLASSDESC {
		classDesc.IsProxyClass = true
		classDesc.ProxyClassDesc, err = readTCProxyClassDesc(stream)
	} else {
		err = fmt.Errorf("ClassDesc flag must be JAVA_TC_CLASSDESC or JAVA_TC_PROXYCLASSDESC, %v found on index %v", flag, stream.CurrentIndex())
	}

	if err != nil {
		return nil, err
	}

	return classDesc, nil
}
