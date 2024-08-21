package checks

import (
	"encoding/json"
	"hana/config"
	"hana/logger"
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
    "results":
    [
        {
            "check_name": "<check_name_#1>",
            "errors": false,
			"error_list":[],
            "issues": true,
            "result": "<base64 encoded string>"
        },
        {
            "check_name": "<check_name_#2>",
            "errors": true,
			"error_list":[
				"check_error_#1",
				"check_error_#2"
			],
            "issues": false,
            "result": ""
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
	Out.ServerIP = config.Conf.Host
	Out.ServerPort = config.Conf.Database.Port
	Out.Sid = config.Conf.SID
	for _, check := range CheckList {
		if check.Error != nil {
			Out.SkippedChecks = append(Out.SkippedChecks, check.Name)
			Out.Checks = append(Out.Checks, CheckOutput{
				CheckName: check.Name,
				Errors:    true,
				ErrorList: []string{check.Error.Error()},
				Issues:    false,
				Result:    Result{},
			})
		} else {
			Out.Checks = append(Out.Checks, CheckOutput{
				CheckName: check.Name,
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
	jsonData, err := json.MarshalIndent(Out, "", "  ")
	if err != nil {
		logger.Log.Errorf("Error marshalling to JSON: %s", err.Error())
		return
	}
	logger.Log.Infof("Writing output data to file: %s\n", outputFile)
	if err := os.WriteFile(outputFile, jsonData, 0666); err != nil {
		logger.Log.Errorf("Error while writing output to '%s': %s\n", outputFile, err.Error())
	}
}
