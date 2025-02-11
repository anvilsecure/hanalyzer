package checks

import (
	"encoding/json"
	"hana/config"
	"hana/logger"
	"hana/utils"
	"io"
	"os"
)

var Out *Output = &Output{}

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
	Errors        bool     `json:"errors"`
	ErrorList     []string `json:"error_list"`
	Issues        bool     `json:"issues"`
	Result        Result   `json:"result"`
}

type ScanDetails struct {
	ScanType       string   `json:"scan_type"`
	ServerIP       string   `json:"server_ip"`
	ServerPort     int      `json:"server_port"`
	Sid            string   `json:"sid"`
	UserName       string   `json:"user_name"`
	ExecutedChecks []string `json:"executed_checks"`
	SkippedChecks  []string `json:"skipped_checks"`
	Categories     []string `json:"categories"`
}

type Output struct {
	ScansDetails []ScanDetails `json:"scan_details"`
	Checks       []CheckOutput `json:"checks"`
}

func CollectOutput(outputFile string, checkType string) {
	var jsonData []byte
	var scanDetails ScanDetails
	exists, empty, err := utils.FileExistsAndNotEmpty(outputFile)
	if err != nil {
		logger.Log.Errorf("Error while checking file '%s' existence: %s\n", outputFile, err.Error())
	}
	if checkType == "query" {
		scanDetails = ScanDetails{
			ScanType:       checkType,
			ServerIP:       config.Conf.Host,
			ServerPort:     config.Conf.Database.Port,
			Sid:            config.Conf.SID,
			UserName:       config.Conf.Database.Username,
			ExecutedChecks: []string{},
			SkippedChecks:  []string{},
		}
	} else if checkType == "ssh" {
		scanDetails = ScanDetails{
			ScanType:       checkType,
			ServerIP:       config.Conf.Host,
			ServerPort:     config.Conf.SSH.Port,
			Sid:            "",
			UserName:       config.Conf.SSH.Username,
			ExecutedChecks: []string{},
			SkippedChecks:  []string{},
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
	logger.Log.Infof("Writing output data to file: %s\n", outputFile)
	if err := os.WriteFile(outputFile, jsonData, 0666); err != nil {
		logger.Log.Errorf("Error while writing output to '%s': %s\n", outputFile, err.Error())
	}
}
