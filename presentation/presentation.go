package presentation

import (
	"encoding/json"
	"hana/logger"
	"html/template"
	"io"
	"os"
	"path/filepath"
)

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
		"groupByCategory": groupByCategory,
		"hasPrefix":       hasPrefix,
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
	out.Categories = extractCategories(out.Checks)
	err = tmpl.ExecuteTemplate(fileOut, "template.html", out)
	if err != nil {
		panic(err)
	}

	println("HTML file generated successfully: output.html")
}
