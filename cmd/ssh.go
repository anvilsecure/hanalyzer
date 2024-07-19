package cmd

import (
	"fmt"
	"hana/checks"
	"hana/config"
	"hana/logger"
	"hana/ssh"
	"log"
	"os"

	"github.com/spf13/cobra"
)

var (
	sshUsername string
	sshPassword string
	sshPort     int
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
			config.Conf.Host = host
			config.Conf.SSH.Port = sshPort
			config.Conf.SSH.Username = sshUsername
			config.Conf.SSH.Password = sshPassword
		}
		ssh.Config()
		checks.CreateChecks(checkType)
		checks.ExecuteChecks(checkType)
		checks.EvaluateResults(checkType)
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
		if sshPassword == "" {
			return fmt.Errorf("error: password required when not using -conf")
		}
	}
	return nil
}

func init() {
	sshCmd.Flags().StringVar(&configFile, "conf", "", "Provide configuration file (required if --host, --ssh-port, --ssh-username, and --ssh-password are not provided by CLI)")
	sshCmd.Flags().StringVar(&host, "host", "", "Database host")
	sshCmd.Flags().IntVar(&sshPort, "ssh-port", 22, "SSH username")
	sshCmd.Flags().StringVar(&sshUsername, "ssh-username", "", "SSH username")
	sshCmd.Flags().StringVar(&sshPassword, "ssh-password", "", "SSH password")
	rootCmd.AddCommand(sshCmd)
}
