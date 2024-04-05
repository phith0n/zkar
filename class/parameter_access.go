package class

type ParameterAccessFlag uint16

const (
	ParameterAccFinal     ParameterAccessFlag = 0x0010
	ParameterAccSynthetic ParameterAccessFlag = 0x1000
	ParameterAccMandated  ParameterAccessFlag = 0x8000
)

func (caf ParameterAccessFlag) HasAccessFlag(flag ParameterAccessFlag) bool {
	return (flag & caf) == flag
}
