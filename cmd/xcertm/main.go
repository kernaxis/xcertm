package main

import (
	"context"
	"os"

	"github.com/kernaxis/xcertm/internal/cli"
)

// version can be set at build time with -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

func main() {
	os.Exit(cli.Run(context.Background(), os.Args, version, os.Stdout, os.Stderr))
}
