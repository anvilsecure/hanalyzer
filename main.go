package main

import (
	"hana/checks"
	"hana/db"
)

func main() {
	for _, check := range checks.AllChecks {
		db.Query(check)
	}
}
