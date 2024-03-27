package main

import (
	"hana/checks"
)

func main() {
	for _, check := range checks.AllChecks {
		check.ExecuteQuery()
	}
}
