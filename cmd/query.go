package cmd

import (
	"fmt"
	"hana/checks"
	"hana/config"
	"hana/db"
	"hana/logger"
	"hana/presentation"
	"hana/utils"
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var queryCmd = &cobra.Command{
	Use:   "query",
	Short: "Perform checks by querying the DB.",
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
		checkType := checks.QueryType
		if err := validateDBFlags(); err != nil {
			logger.Log.Error(err.Error())
			cmd.Help()
			os.Exit(1)
		}
		if configFile != "" {
			err := config.LoadConfig(configFile)
			if err != nil {
				logger.Log.Errorf("Error during configuration loading: %s\n", err.Error())
				os.Exit(1)
			}
		} else {
			dbPassword = os.Getenv("HANA_DB_PASSWORD")
			if dbPassword == "" {
				logger.Log.Error("Environment variable HANA_DB_PASSWORD is empty or not set.")
				logger.Log.Info("Please provide the DB password by setting it:\nexport HANA_DB_PASSWORD=myverysecretpassword")
				os.Exit(1)
			}
			config.Conf.Host = host
			config.Conf.SID = SID
			config.Conf.Database.Port = dbPort
			config.Conf.Database.Username = dbUsername
			config.Conf.Database.Password = dbPassword
		}

		db.Config()
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

func validateDBFlags() error {
	if configFile != "" && (host != "" ||
		SID != "" ||
		dbUsername != "") {
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
	}
	return nil
}

func init() {
	queryCmd.Flags().StringVar(&configFile, "conf", "", "Provide configuration file (required if --host, --db-port, --db-username, --db-password, and --sid are not provided by CLI)")
	queryCmd.Flags().StringVar(&host, "host", "", "Database host")
	queryCmd.Flags().IntVar(&dbPort, "db-port", 39015, "Database port")
	queryCmd.Flags().StringVar(&dbUsername, "db-username", "", "Database username")
	queryCmd.Flags().StringVar(&SID, "sid", "", "Instance SID")
	queryCmd.Flags().StringVar(&outputFolder, "output-folder", "", "Output folder")
	rootCmd.AddCommand(queryCmd)
}
