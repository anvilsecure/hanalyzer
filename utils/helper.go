package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var (
	OutputPath string
)

func PrepareOutputFolder() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("reading CWD: %s", err.Error())
	}
	OutputPath = filepath.Join(cwd, fmt.Sprintf("%s_hana_output", time.Now().Format("20060102_150405")))
	err = os.MkdirAll(OutputPath, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("creating folder '%s': %s", OutputPath, err.Error())
	}
	return OutputPath, nil
}
