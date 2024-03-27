package db

import (
	"database/sql"
	"fmt"
	"hana/config"
	"log"

	_ "github.com/SAP/go-hdb/driver"
)

// DB is a wrapper struct around sql.DB
type Database struct {
	*sql.DB
}

type Results []map[string]interface{}

var (
	dbConfig     config.DatabaseConfig
	hdbDsnFormat string = "hdb://%s:%s@%s:%d"
	hdbDsn       string
	DB           *Database
	sqlDB        *sql.DB
)

const (
	DRIVERNAME = "hdb"
)

func init() {
	dbConfig = config.DBConfig
	hdbDsn = fmt.Sprintf(
		hdbDsnFormat,
		dbConfig.Database.Username,
		dbConfig.Database.Password,
		dbConfig.Database.Host,
		dbConfig.Database.Port,
	)
	err := connect()
	if err != nil {
		log.Panic(err)
	}
	//fmt.Println(sqlDB)
	//defer sqlDB.Close()
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
	//fmt.Printf("\nRes before rows.Next(): %v\n\n", res)
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
		//fmt.Println(myMap)
		//fmt.Printf("Res at iteration #%d: %v\n\n\n", counter, res)
		counter++
	}
	//fmt.Println(res)
	return res
}
