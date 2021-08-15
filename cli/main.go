package main

import (
	"fmt"
	"github.com/phith0n/zkar"
	"github.com/urfave/cli/v2"
	"io/ioutil"
	"os"
)


func main() {
	var app = cli.App{
		Name: "zkar",
		Usage: "A Java serialization tool",
		Commands: []*cli.Command {
			{
				Name: "parse",
				Usage: "parse the Java serialization streams and dump the information",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name: "file",
						Aliases: []string{"f"},
						Usage: "serialization data filepath",
						Required: true,
					},
				},
				Action: func(context *cli.Context) error {
					var filename = context.String("file")
					data, err := ioutil.ReadFile(filename)
					if err != nil {
						return err
					}

					ois := zkar.NewObjectInputStream()
					err = ois.Read(data)
					if err != nil {
						return nil
					}

					fmt.Println(ois.ToString())
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
