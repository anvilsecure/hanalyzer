package cmd

import (
	"fmt"
	"hana/checks"
	"hana/config"
	"hana/logger"
	"hana/presentation"
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
		// ----------------------------------
		//      prepare output folder
		// ----------------------------------
		outputPath, err := utils.PrepareOutputFolder(outputFolder)
		if err != nil {
			log.Fatalf("error while preparing output folder: %s\n", err.Error())
		}
		logger.Log = logger.NewLogger(outputPath)
		jsonOutput = filepath.Join(logger.Log.OutputFolder, outputFileName)
		// ----------------------------------
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
			// if --priv-key is passed, take that value, otherwis it'll be nil
			config.Conf.SSH.PrivateKey = sshPrivKey
			// read SSH PASSWORD from env variable
			sshPassword = os.Getenv("HANA_SSH_PASSWORD")
			// if SSH PASSWORD is empty and also the password for the priv key
			// then exit, otherwise one of them is used
			if sshPassword == "" && sshPrivKey == "" {
				logger.Log.Error("Environment variable HANA_SSH_PASSWORD is empty or not set and no private key was provided.")
				logger.Log.Info("Either provide a private key or set the environment variable HANA_SSH_PASSWORD by setting it:\nexport HANA_SSH_PASSWORD=myverysecretpassword")
				os.Exit(1)
			}
			// SSH private key is provided
			if sshPrivKey != "" {
				// read SSH priv key password from env variable
				sshPrivKeyPass := os.Getenv("HANA_SSH_PRIV_KEY_PASSWORD")
				// if it's empty, then exit
				/*if sshPrivKeyPass == "" {
					logger.Log.Error("Environment variable HANA_SSH_PRIV_KEY_PASSWORD is empty or not set")
					logger.Log.Info("Provide a private key password by setting it:\nexport HANA_SSH_PRIV_KEY_PASSWORD=myverysecretpassword")
					os.Exit(1)
				}*/
				// otherwise set it as priv key password in the SSH config
				config.Conf.SSH.PrivateKeyPassword = sshPrivKeyPass
			} else { // SSH private key is not provided, then the password must have been provided
				config.Conf.SSH.Password = sshPassword
			}
			config.Conf.Host = host
			config.Conf.SSH.Port = sshPort
			config.Conf.SSH.Username = sshUsername
			config.Conf.SSH.IgnoreHostKey = sshIgnoreHostKey
		}
		ssh.Config()
		checks.CURRENT_CHECK_TYPE = checkType.String()
		checks.CreateChecks(checkType)
		checks.ExecuteChecks(checkType)
		checks.EvaluateResults(checkType)
		for _, check := range checks.CheckList {
			if check.Error != nil {
				logger.Log.Warnf("error occurred to check \"%s\": %s\n", check.Name, check.Error.Error())
				checks.SkippedChecks = append(checks.SkippedChecks, check)
			}
		}
		checks.CollectOutput(jsonOutput, checkType.String())
		presentation.Render(utils.OutputPath)
		logger.Log.CloseFile()
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
	sshCmd.Flags().BoolVar(&sshIgnoreHostKey, "ignore-host-key", false, "Ignore host key error")
	sshCmd.Flags().StringVar(&sshPrivKey, "priv-key", "", "SSH private key")
	rootCmd.AddCommand(sshCmd)
}
