package serz

import (
	"fmt"
)

type WalkCallback func(object Object) error
type FindCallback func(object Object) bool
type StopWalkError struct{}

type AllowWalked interface {
	Walk(callback WalkCallback) error
}

func (s *StopWalkError) Error() string {
	return "stop walk"
}

func FindObject(orig AllowWalked, callback FindCallback) Object {
	var result Object
	err := orig.Walk(func(object Object) error {
		if callback(object) {
			result = object
			return new(StopWalkError)
		}

		return nil
	})

	if _, ok := err.(*StopWalkError); ok {
		return result
	} else {
		return nil
	}
}

func FindClassDesc(orig AllowWalked, name string) (*TCClassDesc, error) {
	var obj = FindObject(orig, func(object Object) bool {
		var desc *TCClassDesc
		var ok bool
		if desc, ok = object.(*TCClassDesc); !ok {
			return false
		}

		return desc.ClassName.Data == name
	})

	if obj != nil {
		return obj.(*TCClassDesc), nil
	} else {
		return nil, fmt.Errorf("class desc %v not found", name)
	}
}
