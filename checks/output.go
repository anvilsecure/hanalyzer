package checks

import (
	"encoding/json"
	"hana/config"
	"hana/logger"
	"hana/utils"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
)

var Out *Output = &Output{}

func CollectOutput(outputFile string, checkType string) {
	var jsonData []byte
	var scanDetails ScanDetails
	scanUUID := uuid.New()
	timestamp := time.Now().Format(logTimeFormat)

	cfg := config.Get()

	exists, empty, err := utils.FileExistsAndNotEmpty(outputFile)
	if err != nil {
		logger.Log.Errorf("Error while checking file '%s' existence: %s\n", outputFile, err.Error())
	}
	if checkType == "query" {
		scanDetails = ScanDetails{
			ScanType:       checkType,
			ServerIP:       cfg.Host,
			ServerPort:     cfg.Database.Port,
			Sid:            cfg.SID,
			UserName:       cfg.Database.Username,
			ExecutedChecks: []string{},
			SkippedChecks:  []string{},
			UUID:           scanUUID,
			Timestamp:      timestamp,
		}
	} else if checkType == "ssh" {
		scanDetails = ScanDetails{
			ScanType:       checkType,
			ServerIP:       cfg.Host,
			ServerPort:     cfg.SSH.Port,
			Sid:            "",
			UserName:       cfg.SSH.Username,
			ExecutedChecks: []string{},
			SkippedChecks:  []string{},
			UUID:           scanUUID,
			Timestamp:      timestamp,
		}
	}
	if exists && empty || !exists {
		Out.ScansDetails = append(Out.ScansDetails, scanDetails)
		for _, check := range CheckList {
			if check.Error != nil {
				for _, scanDetails := range Out.ScansDetails {
					if scanDetails.ScanType == check.Type.String() {
						scanDetails.SkippedChecks = append(scanDetails.SkippedChecks, check.Name)
					}
				}
				Out.Checks = append(Out.Checks, CheckOutput{
					CheckName:     check.Name,
					CheckType:     string(check.Type),
					CheckCategory: check.Category,
					Link:          check.Link,
					Errors:        true,
					ErrorList:     []string{check.Error.Error()},
					Issues:        false,
					Result:        Result{},
				})
			} else {
				for _, scanDetails := range Out.ScansDetails {
					if scanDetails.ScanType == check.Type.String() {
						scanDetails.ExecutedChecks = append(scanDetails.ExecutedChecks, check.Name)
					}
				}
				Out.Checks = append(Out.Checks, CheckOutput{
					CheckName:     check.Name,
					CheckType:     string(check.Type),
					CheckCategory: check.Category,
					Link:          check.Link,
					Errors:        false,
					ErrorList:     []string{},
					Issues:        check.IssuesPresent,
					Result: Result{
						Message:   check.Out,
						Resources: check.AffectedResources,
						Info:      check.Info,
						Caveat:    check.Caveat,
					},
				})
			}
		}
		jsonData, err = json.MarshalIndent(Out, "", "  ")
		if err != nil {
			logger.Log.Errorf("Error marshalling to JSON: %s", err.Error())
			return
		}
	} else if exists && !empty {
		var PreviousOut *Output
		file, err := os.Open(outputFile)
		if err != nil {
			logger.Log.Errorf("Error opening existing JSON output file '%s': %s", outputFile, err.Error())
			return
		}
		defer file.Close()

		byteValue, _ := io.ReadAll(file)
		err = json.Unmarshal(byteValue, &PreviousOut)
		if err != nil {
			logger.Log.Errorf("error during JSON unmarshalling of the previous results: %s\n", err.Error())
		}
		PreviousOut.ScansDetails = append(PreviousOut.ScansDetails, scanDetails)
		for _, check := range CheckList {
			if !check.In(PreviousOut.Checks) {
				if check.Error != nil {
					for _, scanDetails := range PreviousOut.ScansDetails {
						if scanDetails.ScanType == check.Type.String() {
							scanDetails.SkippedChecks = append(scanDetails.SkippedChecks, check.Name)
						}
					}
					PreviousOut.Checks = append(PreviousOut.Checks, CheckOutput{
						CheckName:     check.Name,
						CheckType:     string(check.Type),
						CheckCategory: check.Category,
						Link:          check.Link,
						Errors:        true,
						ErrorList:     []string{check.Error.Error()},
						Issues:        false,
						Result:        Result{},
					})
				} else {
					for _, scanDetails := range PreviousOut.ScansDetails {
						if scanDetails.ScanType == check.Type.String() {
							scanDetails.ExecutedChecks = append(scanDetails.ExecutedChecks, check.Name)
						}
					}
					PreviousOut.Checks = append(PreviousOut.Checks, CheckOutput{
						CheckName:     check.Name,
						CheckType:     string(check.Type),
						CheckCategory: check.Category,
						Link:          check.Link,
						Errors:        false,
						ErrorList:     []string{},
						Issues:        check.IssuesPresent,
						Result: Result{
							Message:   check.Out,
							Resources: check.AffectedResources,
							Info:      check.Info,
							Caveat:    check.Caveat,
						},
					})
				}
			}
		}
		jsonData, err = json.MarshalIndent(PreviousOut, "", "  ")
		if err != nil {
			logger.Log.Errorf("Error marshalling to JSON: %s", err.Error())
			return
		}
	}
	logger.Log.Infof("Writing output data to file: %s", outputFile)
	if err := os.WriteFile(outputFile, jsonData, 0666); err != nil {
		logger.Log.Errorf("Error while writing output to '%s': %s\n", outputFile, err.Error())
	}
}
