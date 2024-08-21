package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var (
	dbPort            int
	dbUsername        string
	dbPassword        string
	outputPath        string
	sshUsername       string
	sshPassword       string
	sshPort           int
	jsonOutput        string
	defaultJSONOutput string
)

func prepareOutputFolder() error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("reading CWD: %s", err.Error())
	}
	outputPath = filepath.Join(cwd, fmt.Sprintf("%s_hana_output", time.Now().Format("20060102_150405")))
	err = os.MkdirAll(outputPath, os.ModePerm)
	if err != nil {
		return fmt.Errorf("creating folder '%s': %s", outputPath, err.Error())
	}
	return nil
}
