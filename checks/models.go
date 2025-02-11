package checks

import "time"

type CheckType string

type Duration struct {
	Literal string
	Value   time.Duration
}

type Results []map[string]interface{}

type Check struct {
	Type              CheckType
	Name              string
	Category          string
	Description       string
	Link              string
	Recommendation    string
	Control           string
	Results           Results
	Parameters        []string
	IssuesPresent     bool
	Error             error
	Out               string
	AffectedResources []interface{}
	Info              string
	Caveat            string
}

type entity struct {
	Type       string
	Name       string
	Privileges []string
}
