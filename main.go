package main

import (
	"fmt"
	"hana/checks"
)

func main() {
	for _, check := range checks.AllChecks {
		fmt.Printf("Check: %s\n", check.Name)
		check.ExecuteQuery()
		fmt.Println("-----------")
	}
}
