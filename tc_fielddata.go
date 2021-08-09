package javaserialize


type TCFieldData struct {
	TypeCode string
	BData byte // byte in Java
	CData uint32 // char in Java
	DData float64 // double in Java
	FData float32 // float in Java
	IData int32 // int in Java
	JData int64 // long in Java
	SData int16 // short in Java
	ZData bool // bool in Java
	LData Object // object in Java
	// TODO: array data
}
