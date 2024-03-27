package main

import (
	"hana/checks"
)

func main() {
	checks.ExecuteQueries()
	checks.EvaluateResults()
}
