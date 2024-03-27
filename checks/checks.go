package checks

import (
	"fmt"
	"hana/db"
	"log"
	"reflect"
	"time"
)

const (
	checkSystemUser       string = `SELECT USER_NAME, USER_DEACTIVATED, DEACTIVATION_TIME, LAST_SUCCESSFUL_CONNECT FROM "PUBLIC".USERS WHERE USER_NAME = 'SYSTEM'`
	checkPasswordLifetime string = `SELECT	USER_NAME, USER_DEACTIVATED, DEACTIVATION_TIME, LAST_SUCCESSFUL_CONNECT FROM "PUBLIC".USERS WHERE IS_PASSWORD_LIFETIME_CHECK_ENABLED = 'FALSE'`
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
			switch t := val.(type) {
			case []uint8:
				val = string(val.([]uint8))
			case bool:
				val = val.(bool)
			case time.Time:
				_ = t
				x := val.(time.Time)
				val = fmt.Sprint(x.Format("2006-01-02 15:04:05"))
			default:
				if rv := reflect.ValueOf(val); !rv.IsValid() || rv.IsNil() {
					val = "NULL"
				}
			}
			//fmt.Println("Key:", key, "Val:", val, "Value Type:", reflect.TypeOf(val))
			fmt.Printf("%s: %s\n", key, val)
		}
	}
}

func newCheck(name, description, link, recommendation, query string) Check {
	if name == "" || query == "" {
		log.Fatalf("Query creation failed. Name and Query fields required.")
	}
	return Check{
		Name:           name,
		Description:    description,
		Link:           link,
		Recommendation: recommendation,
		Query:          query,
		Raws:           map[string]interface{}{},
		Result:         false,
	}
}

func init() {
	//////////////////////////////////////////////////////////////////////////////
	name := "CheckSystemUser"
	description := "The database user SYSTEM is the most powerful database user with irrevocable system privileges. The SYSTEM user is active after database creation."
	link := "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/45955420940c4e80a1379bc7270cead6.html?version=2.0.05&locale=en-US#system-user"
	recommendation := "Use SYSTEM to create database users with the minimum privilege set required for their duties (for example, user administration, system administration). Then deactivate SYSTEM."
	AllChecks = append(AllChecks, newCheck(
		name,
		description,
		link,
		recommendation,
		checkSystemUser,
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "CheckPasswordLifetime"
	description = "With the exception of internal technical users (_SYS_* users), the default password policy limits the lifetime of user passwords to 182 days (6 months)."
	link = "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/45955420940c4e80a1379bc7270cead6.html?version=2.0.05&locale=en-US#password-lifetime-of-database-users"
	recommendation = "Do not disable the password lifetime check for database users that correspond to real people."
	AllChecks = append(AllChecks, newCheck(
		name,
		description,
		link,
		recommendation,
		checkPasswordLifetime,
	))
	//////////////////////////////////////////////////////////////////////////////
}
