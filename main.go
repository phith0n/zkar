package main

import (
	"fmt"
	"github.com/phith0n/zkar/serz"
	"github.com/urfave/cli/v2"
	"io/ioutil"
	"os"
)

func main() {
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
				Name:  "dump",
				Usage: "parse the Java serz streams and dump the struct",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "file",
						Aliases:  []string{"f"},
						Usage:    "serz data filepath",
						Required: true,
					},
					&cli.BoolFlag{
						Name:     "golang",
						Usage:    "dump the Go language based struct instead of human readable information",
						Required: false,
						Value:    false,
					},
				},
				Action: func(context *cli.Context) error {
					var filename = context.String("file")
					data, err := ioutil.ReadFile(filename)
					if err != nil {
						return err
					}

					obj, err := serz.FromBytes(data)
					if err != nil {
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
