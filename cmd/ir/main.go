package main

import "ir-toolkit/internal/cli"

func main() {
	if err := cli.Execute(); err != nil {
		panic(err)
	}
}