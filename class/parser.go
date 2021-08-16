package class

import "github.com/phith0n/zkar/commons"

func ParseClass(data []byte) (*ClassFile, error) {
	stream := commons.NewStream(data)
	classFile := new(ClassFile)
	err := classFile.readHeader(stream)
	if err != nil {
		return nil, err
	}

	return classFile, nil
}
