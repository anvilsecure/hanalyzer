package checks

import (
	"fmt"
	"hana/db"
	"reflect"
)

const (
	checkSystemUser string = `SELECT USER_DEACTIVATED, DEACTIVATION_TIME, LAST_SUCCESSFUL_CONNECT, IS_PASSWORD_LIFETIME_CHECK_ENABLED FROM "PUBLIC".USERS WHERE USER_NAME = 'SYSTEM'`
)

var AllChecks []Check

type Check struct {
	Name           string
	Description    string
	Link           string
	Recommendation string
	Query          string
	Raws           map[string]interface{}
	Result         bool
}

func (check *Check) ExecuteQuery() {
	res := db.Query(check.Query)
	// Do something with the map
	for _, r := range res {
		for key, val := range r {
			fmt.Println("Key:", key, "Val:", val, "Value Type:", reflect.TypeOf(val))
		}
	}
}

func newCheck(name, description, link, recommendation string) Check {
	return Check{
		Name:           name,
		Description:    description,
		Link:           link,
		Recommendation: recommendation,
		Query:          checkSystemUser,
		Raws:           map[string]interface{}{},
		Result:         false,
	}
}

func init() {
	name := "CheckSystemUser"
	description := "The database user SYSTEM is the most powerful database user with irrevocable system privileges. The SYSTEM user is active after database creation."
	link := "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/45955420940c4e80a1379bc7270cead6.html?version=2.0.05&locale=en-US#system-user"
	recommendation := "Use SYSTEM to create database users with the minimum privilege set required for their duties (for example, user administration, system administration). Then deactivate SYSTEM."
	CheckSystemUser := newCheck(name, description, link, recommendation)
	AllChecks = append(AllChecks, CheckSystemUser)
}
