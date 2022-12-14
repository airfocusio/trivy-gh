package cmd

import (
	"fmt"
	"os"

	"github.com/airfocusio/trivy-gh/internal"
	"github.com/spf13/cobra"
)

var (
	scanCmdDirectory        string
	scanCmdConfig           string
	scanCmdDryRun           bool
	scanCmdIssueCreateLimit int
	scanCmdRegisterFlags    = func(cmd *cobra.Command) {
		cmd.Flags().StringVar(&scanCmdDirectory, "dir", ".", "dir")
		cmd.Flags().StringVarP(&scanCmdConfig, "config", "c", ".trivy-gh.yaml", "config")
		cmd.Flags().BoolVar(&scanCmdDryRun, "dry-run", false, "dry-run")
		cmd.Flags().IntVar(&scanCmdIssueCreateLimit, "issue-create-limit", -1, "issue-create-limit")
	}
	scanCmd = &cobra.Command{
		Version:       Version.Version,
		Use:           "scan",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := scanCmdDirectory
			fileBytes, err := os.ReadFile(internal.FileResolvePath(dir, scanCmdConfig))
			if err != nil {
				return fmt.Errorf("unable to initialize: %w", err)
			}
			config, err := internal.LoadConfig(fileBytes)
			if err != nil {
				return fmt.Errorf("unable to load configuration: %w", err)
			}
			logger := internal.NewLogger(rootCmdVerbose)
			scan := internal.NewScan(logger, *config, dir, scanCmdDryRun, scanCmdIssueCreateLimit)
			return scan.Run()
		},
	}
)

func init() {
	scanCmdRegisterFlags(scanCmd)
}
