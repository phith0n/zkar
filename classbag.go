package zkar

type ClassBag struct {
	Classes []*TCClassDesc
}

func (bag *ClassBag) Add(classDesc *TCClassDesc) {
	bag.Classes = append(bag.Classes, classDesc)
}

func (bag *ClassBag) Merge(newBag *ClassBag) {
	bag.Classes = append(bag.Classes, newBag.Classes...)
}
