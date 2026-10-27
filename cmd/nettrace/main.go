//go:build windows

// Command nettrace monitors the network activity of a Windows executable.
package main

import (
	"os"

	"nettrace/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
