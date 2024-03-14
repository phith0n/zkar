# ZKar

ZKar is a Java serialization protocol analysis tool implement in Go. This tool is still **work in progress**, so no
complete API document and contribution guide.

ZKar provides:

- A Java serialization payloads parser and viewer in pure Go, no CGO or JDK is required
- From the Java serialization protocol to a Go struct
- A Go library that can manipulate the Java serialization data
- WIP: [ysoserial](https://github.com/frohoff/ysoserial) implement in Go
- WIP: Java class bytecodes parser, viewer and manipulation
- WIP: An implementation of RMI/LDAP in Go

## 📦 Installing

Using ZKar is easy. use `go get` to install the ZKar along with the library and its dependencies:

```shell
go get -u github.com/phith0n/zkar
```

Next, use `github.com/phith0n/zkar/*` in your application:

```go
package main

import (
  "fmt"
  "github.com/phith0n/zkar/serz"
  "log"
  "os"
)

func main() {
  data, _ := os.ReadFile("./testcases/ysoserial/CommonsCollections6.ser")
  serialization, err := serz.FromBytes(data)
  if err != nil {
    log.Fatal("parse error")
  }

  fmt.Println(serialization.ToString())
}
```

[Here](serz/tc_utf_test.go) is an example to show how to read an exist payload and modify it to a UTF-8 overlong encoding payload.

## 💻 Command line utility tool

ZKar also provides a command line utility tool that you can use it directly:

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

For example, you are able to dump the payload CommonsBeanutils3 from ysoserial like:

```shell
$ go run main.go dump -f "$(pwd)/testcases/ysoserial/CommonsBeanutils3.ser"
```

[![asciicast](https://asciinema.org/a/Zlrg1yAghjgauGlogwmbF5vP5.svg)](https://asciinema.org/a/Zlrg1yAghjgauGlogwmbF5vP5)

## 🛠 Tests

ZKar is a well-tested tool that passed all ysoserial generated gadgets parsing and rebuilding tests. It means that
gadget generating by ysoserial can be parsed by ZKar, and parsed struts can be converted back into bytes string which is
equal to the original one.

| Gadget              | Package   | Parse | Rebuild | Parse Time |
|---------------------|-----------|-------|---------|------------|
| AspectJWeaver       | ysoserial | ✅     | ✅       | 80.334µs   |
| BeanShell1          | ysoserial | ✅     | ✅       | 782.613µs  |
| C3P0                | ysoserial | ✅     | ✅       | 98.321µs   |
| Click1              | ysoserial | ✅     | ✅       | 573.298µs  |
| Clojure             | ysoserial | ✅     | ✅       | 72.415µs   |
| CommonsBeanutils1   | ysoserial | ✅     | ✅       | 461.15µs   |
| CommonsCollections1 | ysoserial | ✅     | ✅       | 64.484µs   |
| CommonsCollections2 | ysoserial | ✅     | ✅       | 508.918µs  |
| CommonsCollections3 | ysoserial | ✅     | ✅       | 564.071µs  |
| CommonsCollections4 | ysoserial | ✅     | ✅       | 535.449µs  |
| CommonsCollections5 | ysoserial | ✅     | ✅       | 137.609µs  |
| CommonsCollections6 | ysoserial | ✅     | ✅       | 68.753µs   |
| CommonsCollections7 | ysoserial | ✅     | ✅       | 178.549µs  |
| FileUpload1         | ysoserial | ✅     | ✅       | 35.39µs    |
| Groovy1             | ysoserial | ✅     | ✅       | 150.991µs  |
| Hibernate1          | ysoserial | ✅     | ✅       | 789.674µs  |
| Hibernate2          | ysoserial | ✅     | ✅       | 168.624µs  |
| JBossInterceptors1  | ysoserial | ✅     | ✅       | 632.581µs  |
| JRMPClient          | ysoserial | ✅     | ✅       | 32.967µs   |
| JRMPListener        | ysoserial | ✅     | ✅       | 38.263µs   |
| JSON1               | ysoserial | ✅     | ✅       | 2.157225ms |
| JavassistWeld1      | ysoserial | ✅     | ✅       | 468.596µs  |
| Jdk7u21             | ysoserial | ✅     | ✅       | 355.01µs   |
| Jython1             | ysoserial | ✅     | ✅       | 216.862µs  |
| MozillaRhino1       | ysoserial | ✅     | ✅       | 1.775193ms |
| MozillaRhino2       | ysoserial | ✅     | ✅       | 409.124µs  |
| Myfaces1            | ysoserial | ✅     | ✅       | 22.997µs   |
| Myfaces2            | ysoserial | ✅     | ✅       | 38.131µs   |
| ROME                | ysoserial | ✅     | ✅       | 485.804µs  |
| Spring1             | ysoserial | ✅     | ✅       | 797.469µs  |
| Spring2             | ysoserial | ✅     | ✅       | 358.041µs  |
| URLDNS              | ysoserial | ✅     | ✅       | 21.502µs   |
| Vaadin1             | ysoserial | ✅     | ✅       | 438.729µs  |
| Wicket1             | ysoserial | ✅     | ✅       | 23.509µs   |
| JDK8u20*            | pwntester | ✅     | ✅       | 529.3µs    |

Notice: For parsing JDK8u20 payload, you should add `--jdk8u20` flag to `dump` command.
As the payload is not a valid serialized data stream, it's necessary to tell ZKar patches the data through this flag.

## 📝 TODO

- [ ] Java bytecodes parser and generator
- [x] JDK/JRE 8u20 Gadget supporting
- [ ] Serialization payloads generator
- [ ] An implementation of RMI/LDAP in Go
- [x] Support read/write UTF-8 overlong encoding feature

## ⚖️ License

ZKar is released under the MIT license. See [LICENSE](LICENSE)

## 👀 See Also

- [SerializationDumper](https://github.com/NickstaDB/SerializationDumper): A tool to dump and rebuild Java serialization
  streams and Java RMI packet contents in a more human readable form.
- [ysoserial](https://github.com/frohoff/ysoserial): A proof-of-concept tool for generating payloads that exploit unsafe
  Java object deserialization.
- [Java-Deserialization-Cheat-Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet): The cheat sheet about
  Java Deserialization vulnerabilities
