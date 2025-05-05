package db

import (
	"database/sql"
	"fmt"
	"hana/config"
	"hana/logger"
	"os"
	"time"

	"github.com/theckman/yacspin"

	_ "github.com/SAP/go-hdb/driver"
)

// DB is a wrapper struct around sql.DB
type Database struct {
	*sql.DB
}

type Results []map[string]interface{}

var (
	host         string
	dbConfig     config.DBConfig
	hdbDsnFormat string = "hdb://%s:%s@%s:%d"
	hdbDsn       string
	DB           *Database
	sqlDB        *sql.DB
	username     string
	password     string
)

const (
	DRIVERNAME = "hdb"
)

func validateDBConfiguration() error {
	conf := config.Get()
	if conf.Host == "" {
		return fmt.Errorf("empty host provided for DB connection")
	}
	if conf.SID == "" {
		return fmt.Errorf("empty DB SID provided for DB connection")
	}
	dbConfig = conf.Database
	if dbConfig.Username == "" {
		return fmt.Errorf("empty username provided for DB connection")
	}
	if dbConfig.Password == "" {
		return fmt.Errorf("empty password provided for DB connection")
	}
	host = conf.Host
	username = dbConfig.Username
	password = dbConfig.Password
	return nil
}

func Config() {
	if err := validateDBConfiguration(); err != nil {
		logger.Log.Errorf("configuration validation error: %s\n", err.Error())
		os.Exit(1)
	}
	hdbDsn = fmt.Sprintf(
		hdbDsnFormat,
		username,
		password,
		host,
		dbConfig.Port,
	)
	cfg := yacspin.Config{
		Frequency:         100 * time.Millisecond,
		CharSet:           yacspin.CharSets[78],
		Suffix:            fmt.Sprintf(" connection in progress to %s:%d", host, dbConfig.Port),
		SuffixAutoColon:   true,
		StopCharacter:     "✓",
		StopColors:        []string{"fgGreen"},
		StopFailCharacter: "✗",
		StopFailColors:    []string{"fgRed"},
	}

	spinner, err := yacspin.New(cfg)
	if err != nil {
		logger.Log.Error(err.Error())
	}
	if err = spinner.Start(); err != nil {
		logger.Log.Error(err.Error())
	}
	if err := connect(); err != nil {
		if spinnerErr := spinner.StopFail(); spinnerErr != nil {
			logger.Log.Error(spinnerErr.Error())
			os.Exit(1)
		}
		logger.Log.Error(err.Error())
		logger.Log.CloseFile()
		os.Exit(1)
	}
	if err = spinner.Stop(); err != nil {
		logger.Log.Error(err.Error())
	}
	logger.Log.Infof("Connection successful to %s:%d", host, dbConfig.Port)
}

func connect() error {
	var err error
	sqlDB, err = sql.Open(DRIVERNAME, hdbDsn)
	if err != nil {
		return err
	}

	if err := sqlDB.Ping(); err != nil {
		return err
	}
	return err
}

func Query(q string) (Results, error) {
	var res Results
	rows, err := sqlDB.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	// get the column names from the query
	colNames, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	cols := make([]interface{}, len(colNames))
	colPtrs := make([]interface{}, len(colNames))
	for i := 0; i < len(colNames); i++ {
		colPtrs[i] = &cols[i]
	}
	counter := 0
	for rows.Next() {
		err = rows.Scan(colPtrs...)
		if err != nil {
			return nil, err
		}
		var myMap = make(map[string]interface{})
		for i, col := range cols {
			myMap[colNames[i]] = col
		}
		res = append(res, myMap)
		counter++
	}
	return res, nil
}
