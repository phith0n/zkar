package core

type Thread struct {
	pc int
}

func NewThread() *Thread {
	return &Thread{pc: 0}
}

func (self *Thread) PC() int {
	return self.pc
}
func (self *Thread) SetPC(pc int) {
	self.pc = pc
}
