package presentation

import (
	"embed"
	_ "embed"
	"encoding/json"
	"hana/checks"
	"hana/logger"
	"io"
	"os"
	"path/filepath"
	"text/template"
)

//go:embed static/template.html
var tmplFile embed.FS

func Render(path string) {
	file, err := os.Open(filepath.Join(path, outputFile))
	if err != nil {
		logger.Log.Errorf("Error opening existing JSON output file '%s': %s", outputFile, err.Error())
		return
	}
	defer file.Close()

	byteValue, _ := io.ReadAll(file)
	var out *checks.Output
	err = json.Unmarshal(byteValue, &out)
	if err != nil {
		panic(err)
	}

	tmpl, err := template.New("template.html").Funcs(template.FuncMap{
		"groupByCategory":   groupByCategory,
		"hasPrefix":         hasPrefix,
		"scanDetailsOfType": scanDetailsOfType,
		"prettifyJSON":      prettifyJSON,
		"generateRandomID":  generateRandomID,
	}).ParseFS(tmplFile, "static/template.html")
	if err != nil {
		logger.Log.Error(err.Error())
		os.Exit(1)
	}

	// Create an HTML file
	fileOut, err := os.Create(filepath.Join(path, "output.html"))
	if err != nil {
		logger.Log.Error(err.Error())
		os.Exit(1)
	}
	defer fileOut.Close()

	var sshScanDetails, queryScanDetails checks.ScanDetails
	queryScanDetails, err = scanDetailsOfType(out.ScansDetails, checks.QueryType.String())
	if err == nil {
		queryScanDetails.Categories = extractCategories(out.Checks, checks.QueryType.String())
	}
	sshScanDetails, _ = scanDetailsOfType(out.ScansDetails, checks.SSHType.String())
	if err == nil {
		sshScanDetails.Categories = extractCategories(out.Checks, checks.SSHType.String())
	}

	// Execute the template and write to the file
	err = tmpl.ExecuteTemplate(fileOut, "template.html", struct {
		CheckType        string               `json:"CheckType"`
		Checks           []checks.CheckOutput `json:"Checks"`
		SSHScanDetails   checks.ScanDetails   `json:"SSHScanDetails"`
		QueryScanDetails checks.ScanDetails   `json:"QueryScanDetails"`
	}{
		CheckType:        checks.CURRENT_CHECK_TYPE,
		Checks:           out.Checks,
		SSHScanDetails:   sshScanDetails,
		QueryScanDetails: queryScanDetails,
	})
	if err != nil {
		panic(err)
	}

	logger.Log.Info("HTML file generated successfully: output.html")
}
