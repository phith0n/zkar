package javaserialize

type ClassBag struct {
	Classes []*TCNormalClassDesc
}

func (bag *ClassBag) Add(classDesc *TCNormalClassDesc) {
	bag.Classes = append(bag.Classes, classDesc)
}

func (bag *ClassBag) Merge(newBag *ClassBag) {
	bag.Classes = append(bag.Classes, newBag.Classes...)
}
