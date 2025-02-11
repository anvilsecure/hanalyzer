package checks

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
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
	Link              Link
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

type Result struct {
	Message   string        `json:"message"`
	Resources []interface{} `json:"resources"`
	Info      string        `json:"info"`
	Caveat    string        `json:"caveat"`
}

type CheckOutput struct {
	CheckName     string   `json:"check_name"`
	CheckType     string   `json:"check_type"`
	CheckCategory string   `json:"check_category"`
	Link          Link     `json:"link"`
	Errors        bool     `json:"errors"`
	ErrorList     []string `json:"error_list"`
	Issues        bool     `json:"issues"`
	Result        Result   `json:"result"`
}

type Link struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

type ScanDetails struct {
	ScanType       string    `json:"scan_type"`
	ServerIP       string    `json:"server_ip"`
	ServerPort     int       `json:"server_port"`
	Sid            string    `json:"sid"`
	UserName       string    `json:"user_name"`
	ExecutedChecks []string  `json:"executed_checks"`
	SkippedChecks  []string  `json:"skipped_checks"`
	Categories     []string  `json:"categories"`
	Timestamp      string    `json:"timestamp"`
	UUID           uuid.UUID `json:"uuid"`
}

type Output struct {
	ScansDetails []ScanDetails `json:"scan_details"`
	Checks       []CheckOutput `json:"checks"`
}
