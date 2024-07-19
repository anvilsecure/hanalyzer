package cmd

import (
	"hana/logger"
	"os"

	"github.com/spf13/cobra"
)

var (
	configFile string
	host       string
	SID        string
)

var rootCmd = &cobra.Command{
	Use:   "sap",
	Short: "SAP Hana Configuration Analyzer",
	Long:  "Tool to analyze SAP Hana database configuration against official SAP guidelines.",
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		logger.Log.Error(err.Error())
		os.Exit(1)
	}
}
