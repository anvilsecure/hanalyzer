package db

import (
	"database/sql"
	"fmt"
	"hana/config"
	"hana/logger"
	"log"
	"os"

	_ "github.com/SAP/go-hdb/driver"
)

// DB is a wrapper struct around sql.DB
type Database struct {
	*sql.DB
}

type Results []map[string]interface{}

var (
	host         string = config.Conf.Host
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
	conf := config.Conf
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
	err := connect()
	if err != nil {
		log.Panic(err)
	}
}

func connect() error {
	var err error
	sqlDB, err = sql.Open(DRIVERNAME, hdbDsn)
	if err != nil {
		log.Panic(err)
		return err
	}

	if err := sqlDB.Ping(); err != nil {
		log.Panic(err)
		return err
	}
	return err
}

func Query(q string) Results {
	var res Results
	rows, err := sqlDB.Query(q)
	defer rows.Close()
	if err != nil {
		log.Fatal(err)
	}
	// get the column names from the query
	colNames, err := rows.Columns()
	if err != nil {
		log.Fatal(err)
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
			log.Fatal(err)
		}
		var myMap = make(map[string]interface{})
		for i, col := range cols {
			myMap[colNames[i]] = col
		}
		res = append(res, myMap)
		counter++
	}
	return res
}
