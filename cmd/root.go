package cmd

import (
	"github.com/spf13/cobra"
)

var (
	rootCmdVerbose       bool
	rootCmdNoColor       bool
	rootCmdRegisterFlags = func(cmd *cobra.Command) {
		cmd.PersistentFlags().BoolVarP(&rootCmdVerbose, "verbose", "v", false, "")
		cmd.PersistentFlags().BoolVar(&rootCmdNoColor, "no-color", false, "no-color")
		scanCmdRegisterFlags(cmd)
	}
	rootCmd = &cobra.Command{
		Use:           "trivy-gh",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          scanCmd.RunE,
	}
)

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmdRegisterFlags(rootCmd)
}
