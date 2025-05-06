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
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var queryCmd = &cobra.Command{
	Use:   "query",
	Short: "Perform checks by querying the DB.",
	Run: func(cmd *cobra.Command, args []string) {
		cfg := config.Get()

		// ----------------------------------
		//      prepare output folder
		// ----------------------------------
		outputPath, err := utils.PrepareOutputFolder(outputFolder)
		if err != nil {
			log.Fatalf("error while preparing output folder: %s\n", err.Error())
		}

		logger.SetOutput(outputPath)
		jsonOutput = filepath.Join(outputFolder, outputFileName)

		// ----------------------------------
		checkType := checks.QueryType
		if err := validateDBFlags(); err != nil {
			slog.Error(err.Error())
			cmd.Help()
			os.Exit(1)
		}

		if configFile != "" {
			cfg = config.LoadFromFile(configFile)
		} else {
			dbPassword = os.Getenv("HANA_DB_PASSWORD")
			if dbPassword == "" {
				slog.Error("Environment variable HANA_DB_PASSWORD is empty or not set.")
				slog.Info("Please provide the DB password by setting it:\nexport HANA_DB_PASSWORD=myverysecretpassword")
				os.Exit(1)
			}
			cfg.Host = host
			cfg.SID = SID
			cfg.Database.Port = dbPort
			cfg.Database.Username = dbUsername
			cfg.Database.Password = dbPassword
		}

		db.Config()
		checks.CURRENT_CHECK_TYPE = checkType.String()
		checks.CreateChecks(checkType)
		checks.ExecuteChecks(checkType)
		checks.EvaluateResults(checkType)

		for _, check := range checks.CheckList {
			if check.Error != nil {
				slog.Warn("error occurred to check", "name", check.Name, "error", check.Error.Error())
				checks.SkippedChecks = append(checks.SkippedChecks, check)
			}
		}

		checks.CollectOutput(jsonOutput, checkType.String())
		presentation.Render(utils.OutputPath)
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
