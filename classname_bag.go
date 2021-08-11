package javaserialize

type ClassBag struct {
	Classes []*TCClassDesc
}

func (bag *ClassBag) Add(classDesc *TCClassDesc) {
	bag.Classes = append(bag.Classes, classDesc)
}
