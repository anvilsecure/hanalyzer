package checks

import "fmt"

func (check Check) evaluateCheckSystemUser() {
	// define variables
	var message, info, caveat string
	var errorMessage error
	var issuesPresent bool
	var affectedResources []interface{}

	// chek if the result is empty
	if check.checkEmptyResult() {
		errorMessage = fmt.Errorf("possible error: no user found. Please check it manually")
	} else {
		// actual logic
		if check.Results[0]["USER_DEACTIVATED"] == "TRUE" {
			message = fmt.Sprintf(
				"[+] User SYSTEM is DEACTIVATED (USER_DEACTIVATED=%s).\n",
				check.Results[0]["USER_DEACTIVATED"],
			)
			info = fmt.Sprintf(
				"It was deactivated in date %s and last successful connection was in date %s.",
				check.Results[0]["DEACTIVATION_TIME"],
				check.Results[0]["LAST_SUCCESSFUL_CONNECT"],
			)
			issuesPresent = false
			affectedResources = nil
		} else {
			message = fmt.Sprintf(
				"[!] User SYSTEM is ACTIVE (USER_DEACTIVATED=%s).\n",
				check.Results[0]["USER_DEACTIVATED"],
			)
			info = fmt.Sprintf(
				"Last successful connection was in date %s.",
				check.Results[0]["LAST_SUCCESSFUL_CONNECT"],
			)
			issuesPresent = true
			affectedResources = append(check.AffectedResources, "SYSTEM")
		}
	}
	// assign the values to the check struct
	check.Error = errorMessage
	check.Out = message
	check.IssuesPresent = issuesPresent
	check.AffectedResources = affectedResources
	check.Info = info
	check.Caveat = caveat
}
