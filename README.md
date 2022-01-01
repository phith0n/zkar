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

For example, you can dump the payload CommonsBeanutils3 from Ysoserial like:

```shell
$ go run main.go dump -f "$(pwd)/testcases/ysoserial/CommonsBeanutils3.ser"
```

[![asciicast](https://asciinema.org/a/Zlrg1yAghjgauGlogwmbF5vP5.svg)](https://asciinema.org/a/Zlrg1yAghjgauGlogwmbF5vP5)

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
