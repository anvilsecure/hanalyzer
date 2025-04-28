package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	configFile       string
	host             string
	SID              string
	dbPort           int
	dbUsername       string
	dbPassword       string
	sshUsername      string
	sshPassword      string
	sshPort          int
	jsonOutput       string
	outputFolder     string
	sshIgnoreHostKey bool
	sshPrivKey       string
)

const (
	outputFileName = "output.json"
)

var rootCmd = &cobra.Command{
	Use:   "hanalyzer",
	Short: "SAP Hana Configuration Analyzer",
	Long:  "Tool to analyze SAP Hana database configuration against official SAP guidelines.",
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}
