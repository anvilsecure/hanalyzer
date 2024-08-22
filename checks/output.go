package checks

import (
	"encoding/json"
	"hana/config"
	"hana/logger"
	"hana/utils"
	"io"
	"os"
)

/*
{
    "server_ip": "<IP_address_string>",
    "server_port": 123,
    "sid": "<sid>",
    "executed_checks":
    [
        "check_name_#1",
        "check_name_#2"
    ],
    "skipped_checks":
    [
        "check_name_#3",
        "check_name_#4"
    ],
    "checks":
    [
        {
            "check_name": "<check_name_#1>",
			"check_type": "[ssh|query]"
            "errors": true,
			"error_list":[
				"check_error_#1",
				"check_error_#2"
			],
            "issues": false,
            "result": {
				"message": "<result message string>",
				"info": "<info message string>",
				"caveat": "<caveat message string>",
				"resources": [
					{
						"key1": "value1",
						"key2": "value2",
						....
						"keyN": "valueN"
					},
					....
				]
			}
        }
    ]
}
*/

var Out *Output = &Output{}

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

func (check *Check) addCheckResultToOutput(
	message string,
	info string,
	issuesPresent bool,
	affectedReources []interface{},
) {
	check.Out = message
	check.Info = info
	check.IssuesPresent = issuesPresent
	check.AffectedResources = affectedReources
}

func CollectOutput(outputFile string) {
	var jsonData []byte
	exists, empty, err := utils.FileExistsAndNotEmpty(outputFile)
	if err != nil {
		logger.Log.Errorf("Error while checking file '%s' existence: %s\n", outputFile, err.Error())
	}
	if exists && empty || !exists {
		if exists && empty {
			logger.Log.Debugf("File '%s' is empty I will replace it.\n", outputFile)
		}
		Out.ServerIP = config.Conf.Host
		Out.ServerPort = config.Conf.Database.Port
		Out.Sid = config.Conf.SID
		for _, check := range CheckList {
			if check.Error != nil {
				Out.SkippedChecks = append(Out.SkippedChecks, check.Name)
				Out.Checks = append(Out.Checks, CheckOutput{
					CheckName: check.Name,
					CheckType: string(check.Type),
					Errors:    true,
					ErrorList: []string{check.Error.Error()},
					Issues:    false,
					Result:    Result{},
				})
			} else {
				Out.Checks = append(Out.Checks, CheckOutput{
					CheckName: check.Name,
					CheckType: string(check.Type),
					Errors:    false,
					ErrorList: []string{},
					Issues:    check.IssuesPresent,
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
		logger.Log.Debugf("File '%s' is not empty I will add results to it.\n", outputFile)
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
		for _, check := range CheckList {
			if check.Error != nil {
				PreviousOut.SkippedChecks = append(PreviousOut.SkippedChecks, check.Name)
				PreviousOut.Checks = append(PreviousOut.Checks, CheckOutput{
					CheckName: check.Name,
					CheckType: string(check.Type),
					Errors:    true,
					ErrorList: []string{check.Error.Error()},
					Issues:    false,
					Result:    Result{},
				})
			} else {
				PreviousOut.Checks = append(PreviousOut.Checks, CheckOutput{
					CheckName: check.Name,
					CheckType: string(check.Type),
					Errors:    false,
					ErrorList: []string{},
					Issues:    check.IssuesPresent,
					Result: Result{
						Message:   check.Out,
						Resources: check.AffectedResources,
						Info:      check.Info,
						Caveat:    check.Caveat,
					},
				})
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
