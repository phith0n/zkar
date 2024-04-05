package class

import (
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type TypePath struct {
	Path []*TypePathNode
}

type TypePathNode struct {
	TypePathKind      uint8
	TypeArgumentIndex uint8
}

func NewTypePath(stream *commons.Stream) (*TypePath, error) {
	bs, err := stream.ReadN(1)
	if err != nil {
		return nil, fmt.Errorf("read TypePath failed, no enough data in the stream")
	}

	tp := &TypePath{}
	length := bs[0]
	for i := uint8(0); i < length; i++ {
		bs, err = stream.ReadN(2)
		if err != nil {
			return nil, fmt.Errorf("read TypePath Node failed, no enough data in the stream")
		}

		tp.Path = append(tp.Path, &TypePathNode{
			TypePathKind:      bs[0],
			TypeArgumentIndex: bs[1],
		})
	}

	return tp, nil
}
