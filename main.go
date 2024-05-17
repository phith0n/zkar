package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/urfave/cli/v2"

	"github.com/phith0n/zkar/classfile"
	"github.com/phith0n/zkar/core"
	"github.com/phith0n/zkar/global"
	"github.com/phith0n/zkar/serz"
)

func main() {
	log.SetFlags(0)
	var app = cli.App{
		Name:  "zkar",
		Usage: "A Java serz tool",
		Commands: []*cli.Command{
			{
				Name:  "generate",
				Usage: "(WIP) generate Java serialization attack payloads",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "output",
						Usage:    "output file path",
						Aliases:  []string{"o"},
						Required: false,
						Value:    "",
					},
					&cli.BoolFlag{
						Name:     "list",
						Usage:    "list all available gadgets",
						Aliases:  []string{"l"},
						Required: false,
						Value:    false,
					},
				},
				Action: func(context *cli.Context) error {
					return fmt.Errorf("payloads generation feature is working in progress")
				},
			},
			{
				Name:  "export",
				Usage: "export java class file",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "file",
						Aliases:  []string{"f"},
						Usage:    "serz data filepath",
						Required: false,
					},
					&cli.StringFlag{
						Name:     "base64",
						Aliases:  []string{"B"},
						Usage:    "serz data as Base64 format string",
						Required: false,
					},
				},
				Action: func(context *cli.Context) error {
					var filename = context.String("file")
					var b64data = context.String("base64")
					var data []byte
					var err error
					if (filename == "" && b64data == "") || (filename != "" && b64data != "") {
						return fmt.Errorf("one \"file\" or \"base64\" flag must be specified, and not both")
					}

					if filename != "" {
						data, err = ioutil.ReadFile(filename)
					} else {
						data, err = base64.StdEncoding.DecodeString(b64data)
					}

					if err != nil {
						return err
					}

					var obj *serz.Serialization
					obj, err = serz.FromBytes(data)

					var bytesCodes [][]byte
					err = obj.Walk(func(object serz.Object) error {
						v, ok := object.(*serz.TCArray)
						if ok {
							if len(v.ArrayData) > 0 {
								if v.ArrayData[0].TypeCode == "B" {
									var temp []byte
									for _, code := range v.ArrayData {
										temp = append(temp, code.Byte)
									}
									if len(temp) > 4 &&
										// CHECK CAFE
										hex.EncodeToString(temp[:8]) != "CAFEBABE" {
										bytesCodes = append(bytesCodes, temp)
									}
								}
							}
						}
						return nil
					})
					if err != nil {
						return err
					}

					if len(bytesCodes) > 0 {
						for _, v := range bytesCodes {
							classData, err := classfile.Parse(v)
							if err != nil {
								continue
							}
							global.CP = classData.ConstantPool()
							name := classData.ClassName()
							fmt.Println("[*] find java class: " + name)
							for _, m := range classData.Methods() {
								methodName := m.Name()
								if methodName == "<init>" {
									methodName = name + " {}"
								}
								if methodName == "<clinit>" {
									methodName = "static {}"
								}
								fmt.Println("[*] method: " + methodName)
								bytecode := m.CodeAttribute().Code()
								// virtual thread
								thread := core.Thread{}
								reader := &core.BytecodeReader{}
								// save all instructions to struct
								instSet := core.InstructionSet{}
								instSet.ClassName = name
								instSet.MethodName = methodName
								instSet.Desc = m.Descriptor()
								for {
									// read finish
									if thread.PC() >= len(bytecode) {
										break
									}
									// offset
									reader.Reset(bytecode, thread.PC())
									// read instruction
									opcode := reader.ReadUint8()
									inst := core.NewInstruction(opcode)
									// read operands of the instruction
									inst.FetchOperands(reader)
									ops := inst.GetOperands()
									instEntry := core.InstructionEntry{
										Instrument: getInstructionName(inst),
										Operands:   ops,
									}
									var out string
									out += instEntry.Instrument
									out += "\t"
									for _, op := range instEntry.Operands {
										out += op
										out += " "
									}
									fmt.Println("\033[32m" + out + "\033[0m")
									instSet.InstArray = append(instSet.InstArray, instEntry)
									// offset++
									thread.SetPC(reader.PC())
								}
							}
						}
					}

					return nil
				},
			},
			{
				Name:  "dump",
				Usage: "parse the Java serz streams and dump the struct",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "file",
						Aliases:  []string{"f"},
						Usage:    "serz data filepath",
						Required: false,
					},
					&cli.StringFlag{
						Name:     "base64",
						Aliases:  []string{"B"},
						Usage:    "serz data as Base64 format string",
						Required: false,
					},
					&cli.BoolFlag{
						Name:     "golang",
						Usage:    "dump the Go language based struct instead of human readable information",
						Required: false,
						Value:    false,
					},
					&cli.BoolFlag{
						Name: "jdk8u20",
						Usage: "This payload is a JDK8u20 payload generated by " +
							"<https://github.com/pwntester/JRE8u20_RCE_Gadget>",
						Required: false,
						Value:    false,
					},
				},
				Action: func(context *cli.Context) error {
					var filename = context.String("file")
					var b64data = context.String("base64")
					var data []byte
					var err error
					if (filename == "" && b64data == "") || (filename != "" && b64data != "") {
						return fmt.Errorf("one \"file\" or \"base64\" flag must be specified, and not both")
					}

					if filename != "" {
						data, err = ioutil.ReadFile(filename)
					} else {
						data, err = base64.StdEncoding.DecodeString(b64data)
					}

					if err != nil {
						return err
					}

					var obj *serz.Serialization
					if context.Bool("jdk8u20") {
						obj, err = serz.FromJDK8u20Bytes(data)
					} else {
						obj, err = serz.FromBytes(data)
					}
					if err != nil {
						log.Fatalln(err)
						return nil
					}

					if context.Bool("golang") {
						serz.DumpToGoStruct(obj)
					} else {
						fmt.Println(obj.ToString())
					}

					return nil
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err.Error())
	}
}

func getInstructionName(instruction core.Instruction) string {
	// type name -> instruction name
	i := fmt.Sprintf("%T", instruction)
	return strings.Split(i, ".")[1]
}
