package checks

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"
)

type CheckType string

type CheckInt interface {
	Print()
}

func (c Check) Print() {
	rows := [][]interface{}{
		{"Name", c.Name},
		{"Category", c.Category},
		{"Description", c.Description},
		{"Link", c.Link},
		{"Recommendation", c.Recommendation},
		{"Control", c.Control},
		{"Results", c.Results},
		{"Parameters", c.Parameters},
		{"IssuesPresent", c.IssuesPresent},
		{"Error", c.Error},
		{"Out", c.Out},
		{"AffectedResources", c.AffectedResources},
		{"Info", c.Info},
		{"Caveat", c.Caveat},
	}
	// Create a tab writer for proper alignment
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "| Field\t| Value\t| ")   // Header
	fmt.Fprintln(w, "| ------\t| ------\t| ") // Header

	// Print each row
	for _, row := range rows {
		fmt.Fprintf(w, "| %s\t| %s\t|\n", row[0], row[1])
	}

	// Flush the writer to apply formatting
	w.Flush()
}

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
