package serz

func NewNullPointer() *TCClassPointer {
	return &TCClassPointer{
		Flag: JAVA_TC_NULL,
		Null: &TCNull{},
	}
}

func NewUtf(data string) *TCUtf {
	return &TCUtf{Data: data}
}

func NewTCString(data string, handler uint32) *TCString {
	return &TCString{
		Utf:     NewUtf(data),
		Handler: handler,
	}
}

func NewTCStringPointer(data string, handler uint32) *TCStringPointer {
	return &TCStringPointer{
		IsRef:  false,
		String: NewTCString(data, handler),
	}
}

func SimpleClassDesc(className string, svuid int64, flags byte, handler uint32, super *TCClassPointer, fields [][3]string) *TCClassDesc {
	var desc = TCClassDesc{
		ClassName: &TCUtf{
			Data: className,
		},
		SerialVersionUID:  svuid,
		ClassDescFlags:    flags,
		SuperClassPointer: super,
		Handler:           handler,
	}

	for _, blocks := range fields {
		field := &TCFieldDesc{
			TypeCode: blocks[0],
			FieldName: &TCUtf{
				Data: blocks[1],
			},
		}
		if field.TypeCode == "L" || field.TypeCode == "[" {
			handler++
			field.ClassName = NewTCStringPointer(blocks[2], handler)
		}
		desc.Fields = append(desc.Fields, field)
	}

	return &desc
}

func NewTCValueBytes(data []byte) []*TCValue {
	var l []*TCValue
	for _, b := range data {
		value := &TCValue{
			TypeCode: "B",
			Byte:     b,
		}
		l = append(l, value)
	}
	return l
}
