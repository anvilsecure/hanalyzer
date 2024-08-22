package presentation

import (
	"encoding/json"
	"hana/logger"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var (
	Out        *Output = &Output{}
	outputFile         = "out.json"
)

type Result struct {
	Message   string        `json:"message"`
	Resources []interface{} `json:"resources"`
	Info      string        `json:"info"`
	Caveat    string        `json:"caveat"`
}

type CheckOutput struct {
	CheckName string   `json:"check_name"`
	CheckType string   `json:"check_type"`
	Errors    bool     `json:"errors"`
	ErrorList []string `json:"error_list"`
	Issues    bool     `json:"issues"`
	Result    Result   `json:"result"`
}

type Output struct {
	ServerIP       string        `json:"server_ip"`
	ServerPort     int           `json:"server_port"`
	Sid            string        `json:"sid"`
	ExecutedChecks []string      `json:"executed_checks"`
	SkippedChecks  []string      `json:"skipped_checks"`
	Checks         []CheckOutput `json:"checks"`
}

// Function to check if a string starts with a given prefix
func hasPrefix(s, prefix string) bool {
	return strings.HasPrefix(s, prefix)
}

func Render(path string) {
	file, err := os.Open(filepath.Join(path, outputFile))
	if err != nil {
		logger.Log.Errorf("Error opening existing JSON output file '%s': %s", outputFile, err.Error())
		return
	}
	defer file.Close()

	byteValue, _ := io.ReadAll(file)
	var out *Output
	err = json.Unmarshal(byteValue, &out)
	if err != nil {
		panic(err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		logger.Log.Errorf("failed to get CWD: %s\n", err.Error())
		os.Exit(1)
	}
	tmpFileName := filepath.Join(cwd, "static/template.html")
	tmpl, err := template.New("webpage").Funcs(template.FuncMap{
		"hasPrefix": hasPrefix,
	}).ParseFiles(tmpFileName)
	if err != nil {
		panic(err)
	}

	// Create an HTML file
	fileOut, err := os.Create(filepath.Join(path, "output.html"))
	if err != nil {
		panic(err)
	}
	defer fileOut.Close()

	// Execute the template and write to the file
	err = tmpl.ExecuteTemplate(fileOut, "template.html", out)
	if err != nil {
		panic(err)
	}

	println("HTML file generated successfully: output.html")
}
