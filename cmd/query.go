package cmd

import (
	"fmt"
	"hana/checks"
	"hana/config"
	"hana/db"
	"hana/logger"
	"log"
	"os"

	"github.com/spf13/cobra"
)

var (
	dbPort     int
	dbUsername string
	dbPassword string
)

var queryCmd = &cobra.Command{
	Use:   "query",
	Short: "Perform checks by querying the DB.",
	Run: func(cmd *cobra.Command, args []string) {
		checkType := checks.QueryType
		if err := validateDBFlags(); err != nil {
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
			config.Conf.SID = SID
			config.Conf.Database.Port = dbPort
			config.Conf.Database.Username = dbUsername
			config.Conf.Database.Password = dbPassword
		}
		db.Config()
		checks.CreateChecks(checkType)
		checks.ExecuteChecks(checkType)
		checks.EvaluateResults(checkType)
	},
}

func validateDBFlags() error {
	if configFile != "" && (host != "" ||
		SID != "" ||
		dbUsername != "" ||
		dbPassword != "") {
		return fmt.Errorf("error: You cannot use -conf with other CLI flags")
	}
	if configFile == "" {
		if host == "" {
			return fmt.Errorf("error: -host required when not using -conf")
		}
		if SID == "" {
			return fmt.Errorf("error: -sid required when not using -conf")
		}
		if dbUsername == "" {
			return fmt.Errorf("error: username required when not using -conf")
		}
		if dbPassword == "" {
			return fmt.Errorf("error: password required when not using -conf")
		}
	}
	return nil
}

func init() {
	queryCmd.Flags().StringVar(&configFile, "conf", "", "Provide configuration file (required if --host, --db-port, --db-username, --db-password, and --sid are not provided by CLI)")
	queryCmd.Flags().StringVar(&host, "host", "", "Database host")
	queryCmd.Flags().IntVar(&dbPort, "db-port", 39015, "Database port")
	queryCmd.Flags().StringVar(&dbUsername, "db-username", "", "Database username")
	queryCmd.Flags().StringVar(&dbPassword, "db-password", "", "Database password")
	queryCmd.Flags().StringVar(&SID, "sid", "", "Instance SID")
	rootCmd.AddCommand(queryCmd)
}
