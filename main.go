package main

import (
	"os"

	"github.com/airfocusio/trivy-gh/cmd"
	"github.com/airfocusio/trivy-gh/internal"
)

// nolint: gochecknoglobals
var (
	version = "dev"
	commit  = ""
	date    = ""
	builtBy = ""
)

func main() {
	cmd.Version = cmd.FullVersion{Version: version, Commit: commit, Date: date, BuiltBy: builtBy}
	if err := cmd.Execute(); err != nil {
		logger := internal.NewLogger(false)
		logger.Error.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
