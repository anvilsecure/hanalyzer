package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	OutputPath string
)

// PrepareOutputFolder creates the output folder given the input outputFolder
// variable. If it is an empty string the output folder name format will be
// YYYYMMDD_hhmm_hana_output. The output folder will be created in the CWD.
// It returns a string for the absolute path of the outputFolder and an error
// if there was an issue creating the folder.
//
// Parameters:
//
//	outputFolder: the output folder name
//
// Returns:
//   - string: the absolute path of the output folder
//   - error: An error if there was a problem creating the folder,
//     or nil if the operation was successful.
func PrepareOutputFolder(outputFolder string) (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("reading CWD: %s", err.Error())
	}
	if outputFolder == "" {
		OutputPath = filepath.Join(cwd, fmt.Sprintf("%s_hana_output", time.Now().Format("20060102_150405")))
	} else {
		if strings.HasPrefix(outputFolder, "/") {
			OutputPath = outputFolder
		} else {
			OutputPath = filepath.Join(cwd, outputFolder)
		}
	}
	exists, err := FolderExists(OutputPath)
	if err != nil {
		return "", fmt.Errorf("checking if folder '%s' exists: %s", OutputPath, err.Error())
	}
	if !exists {
		err = os.MkdirAll(OutputPath, os.ModePerm)
		if err != nil {
			return "", fmt.Errorf("creating folder '%s': %s", OutputPath, err.Error())
		}
	}
	return OutputPath, nil
}

// FolderExists checks if a folder exists at the specified path.
// It returns a boolean indicating whether the folder exists and an error
// if there was an issue accessing the folder.
//
// Parameters:
//
//	path: The path to the folder you want to check.
//
// Returns:
//   - bool: True if the folder exists, false otherwise.
//   - error: An error if there was a problem checking the folder's existence,
//     or nil if the operation was successful.
func FolderExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// FileExistsAndNotEmpty checks if a file exists at the specified path and
// whether it is empty or not. It returns a boolean indicating whether the
// file exists, a boolean indicating whether the file is empty, and an error
// if there was an issue accessing the file.
//
// Parameters:
//
//	path: The path to the file you want to check.
//
// Returns:
//   - bool: True if the file exists, false otherwise.
//   - bool: True if the file is empty, false if it is not empty or does not exist.
//   - error: An error if there was a problem checking the file's existence,
//     or nil if the operation was successful.
func FileExistsAndNotEmpty(path string) (bool, bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, false, nil
		}
		return false, false, err
	}
	return true, info.Size() == 0, nil
}
