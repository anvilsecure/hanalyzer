package main

import (
	"database/sql"
	"fmt"
	"hana/config"
	"log"

	// Register hdb driver.
	_ "github.com/SAP/go-hdb/driver"
)

const (
	driverName = "hdb"
	//hdbDsn     = "hdb://SYSTEM:Despicable-dishwasher2@host:port"
)

var (
	dbConfig     config.DatabaseConfig
	hdbDsnFormat string = "hdb://%s:%s@%s:%d"
	hdbDsn       string
)

func init() {
	config.LoadConfig()
	dbConfig = config.DBConfig
	hdbDsn = fmt.Sprintf(
		hdbDsnFormat,
		dbConfig.Database.Username,
		dbConfig.Database.Password,
		dbConfig.Database.Host,
		dbConfig.Database.Port,
	)
}

func main() {
	db, err := sql.Open(driverName, hdbDsn)
	if err != nil {
		log.Panic(err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Panic(err)
	}
}
