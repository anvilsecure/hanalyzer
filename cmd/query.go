package cmd

import (
	"fmt"
	"hana/checks"
	"hana/config"
	"hana/db"
	"hana/logger"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

var (
	dbPort            int
	dbUsername        string
	dbPassword        string
	outputPath        string
	jsonOutput        string
	defaultJSONOutput string
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
		if jsonOutput == "" {
			jsonOutput = defaultJSONOutput
		}
	}
	return nil
}

func prepareOutputFolder() error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("reading CWD: %s", err.Error())
	}
	outputPath = filepath.Join(cwd, fmt.Sprintf("%s_hana_output", time.Now().Format("20060102150405")))
	err = os.MkdirAll(outputPath, os.ModePerm)
	if err != nil {
		return fmt.Errorf("creating folder '%s': %s", outputPath, err.Error())
	}
	return nil
}

func init() {
	err := prepareOutputFolder()
	if err != nil {
		logger.Log.Errorf("Error while preparing output folder: %s\n", err.Error())
		os.Exit(1)
	}
	defaultJSONOutput = filepath.Join(outputPath, "out.json")
	queryCmd.Flags().StringVar(&configFile, "conf", "", "Provide configuration file (required if --host, --db-port, --db-username, --db-password, and --sid are not provided by CLI)")
	queryCmd.Flags().StringVar(&host, "host", "", "Database host")
	queryCmd.Flags().IntVar(&dbPort, "db-port", 39015, "Database port")
	queryCmd.Flags().StringVar(&dbUsername, "db-username", "", "Database username")
	queryCmd.Flags().StringVar(&SID, "sid", "", "Instance SID")
	queryCmd.Flags().StringVar(&jsonOutput, "json-output", "", "JSON output file")
	rootCmd.AddCommand(queryCmd)
}
