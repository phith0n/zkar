package serz

import (
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"testing"
)

func TestFindClassDesc(t *testing.T) {
	data, err := ioutil.ReadFile("../testcases/ysoserial/Jdk7u21.ser")
	require.Nil(t, err)

	ser, err := FromBytes(data)
	require.Nil(t, err)

	desc := FindClassDesc(ser, "sun.reflect.annotation.AnnotationInvocationHandler")
	require.NotNil(t, desc)
	require.Equal(t, desc.SerialVersionUID, int64(6182022883658399397))

	// check pointer
	desc.SerialVersionUID = int64(1)
	desc2 := FindClassDesc(ser, "sun.reflect.annotation.AnnotationInvocationHandler")
	require.NotNil(t, desc2)
	require.Equal(t, desc2.SerialVersionUID, int64(1))

	desc3 := FindClassDesc(ser, "not.found.Class")
	require.Nil(t, desc3)
}

func TestWalk(t *testing.T) {
	walkAndTest("../testcases/ysoserial/*.ser", t, func(filename string, data []byte, ser *Serialization) {
		err := ser.Walk(func(object Object) error {
			require.NotNil(t, object)
			return nil
		})
		require.Nil(t, err)
	})
}
