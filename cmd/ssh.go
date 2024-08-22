package cmd

import (
	"fmt"
	"hana/checks"
	"hana/config"
	"hana/logger"
	"hana/ssh"
	"hana/utils"
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "Use SSH to perform the following checks on the DB server:\n\t\t\t- Encryption Key of the SAP HANA Secure User Store",
	Run: func(cmd *cobra.Command, args []string) {
		checkType := checks.SSHType
		if err := validateSSHFlags(); err != nil {
			logger.Log.Error(err.Error())
			cmd.Help()
			os.Exit(1)
		}
		if configFile != "" {
			err := config.LoadConfig(configFile)
			if err != nil {
				log.Fatalf("error during configuration loading: %s\n", err.Error())
			}
		} else {
			sshPassword = os.Getenv("HANA_SSH_PASSWORD")
			if sshPassword == "" {
				logger.Log.Error("Environment variable HANA_SSH_PASSWORD is empty or not set.")
				logger.Log.Info("Please provide the DB password by setting it:\nexport HANA_SSH_PASSWORD=myverysecretpassword")
				os.Exit(1)
			}
			config.Conf.Host = host
			config.Conf.SSH.Port = sshPort
			config.Conf.SSH.Username = sshUsername
			config.Conf.SSH.Password = sshPassword
		}
		// ----------------------------------
		//      prepare output folder
		// ----------------------------------
		log.Println("preparing output folder")
		outputPath, err := utils.PrepareOutputFolder(outputFolder)
		if err != nil {
			log.Fatalf("error while preparing output folder: %s\n", err.Error())
		}
		logger.Log = logger.NewLogger(outputPath)
		logger.Log.Debugf("outputPath: %s\n", logger.Log.OutputFolder)
		jsonOutput = filepath.Join(logger.Log.OutputFolder, "out.json")
		// ----------------------------------

		ssh.Config()
		checks.CreateChecks(checkType)
		checks.ExecuteChecks(checkType)
		checks.EvaluateResults(checkType)
		for _, check := range checks.CheckList {
			if check.Error != nil {
				logger.Log.Warnf("error occurred to check \"%s\": %s\n", check.Name, check.Error.Error())
				checks.SkippedChecks = append(checks.SkippedChecks, check)
			}
		}
		checks.CollectOutput(jsonOutput)
	},
}

func validateSSHFlags() error {
	if configFile != "" && (host != "" ||
		sshUsername != "" ||
		sshPassword != "") {
		return fmt.Errorf("error: You cannot use -conf with other CLI flags")
	}
	if configFile == "" {
		if host == "" {
			return fmt.Errorf("error: -host required when not using -conf")
		}
		if sshUsername == "" {
			return fmt.Errorf("error: username required when not using -conf")
		}
	}
	return nil
}

func init() {
	sshCmd.Flags().StringVar(&configFile, "conf", "", "Provide configuration file (required if --host, --ssh-port, --ssh-username, and --ssh-password are not provided by CLI)")
	sshCmd.Flags().StringVar(&host, "host", "", "Database host")
	sshCmd.Flags().IntVar(&sshPort, "ssh-port", 22, "SSH username")
	sshCmd.Flags().StringVar(&sshUsername, "ssh-username", "", "SSH username")
	sshCmd.Flags().StringVar(&outputFolder, "output-folder", "", "Output folder")
	rootCmd.AddCommand(sshCmd)
}
