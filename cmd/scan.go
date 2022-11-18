package cmd

import (
	"fmt"
	"io/ioutil"

	"github.com/airfocusio/trivy-gh/internal"
	"github.com/spf13/cobra"
)

var (
	scanCmdDirectory        string
	scanCmdDry              bool
	scanCmdIssueCreateLimit int
	scanCmdIssueUpdateLimit int
	scanCmdRegisterFlags    = func(cmd *cobra.Command) {
		cmd.Flags().StringVar(&scanCmdDirectory, "dir", ".", "dir")
		cmd.Flags().BoolVar(&scanCmdDry, "dry", false, "dry")
		cmd.Flags().IntVar(&scanCmdIssueCreateLimit, "issue-create-limit", -1, "issue-create-limit")
		cmd.Flags().IntVar(&scanCmdIssueUpdateLimit, "issue-update-limit", -1, "issue-update-limit")
	}
	scanCmd = &cobra.Command{
		Version:       Version.Version,
		Use:           "scan",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := scanCmdDirectory
			fileBytes, err := ioutil.ReadFile(internal.FileResolvePath(dir, ".trivy-gh.yaml"))
			if err != nil {
				return fmt.Errorf("unable to initialize: %w", err)
			}
			config, err := internal.LoadConfig(fileBytes)
			if err != nil {
				return fmt.Errorf("unable to load configuration: %w", err)
			}
			logger := internal.NewLogger(rootCmdVerbose)
			scan := internal.NewScan(logger, *config, dir, scanCmdDry, scanCmdIssueCreateLimit, scanCmdIssueUpdateLimit)
			return scan.Run()
		},
	}
)

func init() {
	scanCmdRegisterFlags(scanCmd)
}
