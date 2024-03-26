package main

import (
	"database/sql"
	"log"

	// Register hdb driver.
	_ "github.com/SAP/go-hdb/driver"
)

const (
	driverName = "hdb"
	hdbDsn     = "hdb://SYSTEM:Despicable-dishwasher2@host:port"
)

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
