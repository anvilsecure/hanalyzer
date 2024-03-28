package checks

import (
	"fmt"
	"hana/db"
	"hana/utils"
	"log"
	"os"
	"reflect"
	"strings"
	"time"
)

type Check struct {
	Name           string
	Description    string
	Link           string
	Recommendation string
	Query          string
	Results        db.Results
	Parameters     []string
	Result         bool
}

func executeQuery(query string) (results db.Results) {
	res := db.Query(query)
	// Do something with the map
	for _, r := range res {
		var resMap = make(map[string]interface{})
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
			resMap[key] = val
		}
		results = append(results, resMap)
	}
	return
}

func prepareAndExecute(check *Check) {
	for _, p := range check.Parameters {
		stmt := fmt.Sprintf(check.Query, p)
		//fmt.Println(stmt)
		executeQuery(stmt)
	}
}

func ExecuteQueries() {
	for _, check := range AllChecks {
		if len(check.Parameters) == 0 {
			check.Results = executeQuery(check.Query)
		} else {
			prepareAndExecute(check)
		}
	}
}

func EvaluateResults() {
	for _, check := range AllChecks {
		utils.Warning("Check: %s\n", check.Name)
		switch check.Name {
		case "CheckSystemUser":
			if check.Results[0]["USER_DEACTIVATED"] == "TRUE" {
				utils.Ok(
					"[+] User SYSTEM is DEACTIVATED (USER_DEACTIVATED=%s).\n",
					check.Results[0]["USER_DEACTIVATED"],
				)
				utils.Info(
					"It was deactivated in date %s and last successful connection was in date %s.\n",
					check.Results[0]["DEACTIVATION_TIME"],
					check.Results[0]["LAST_SUCCESSFUL_CONNECT"],
				)
			} else {
				utils.Error(
					"[!] User SYSTEM is ACTIVE (USER_DEACTIVATED=%s).\n",
					check.Results[0]["USER_DEACTIVATED"],
				)
				utils.Info(
					"Last successful connection was in date %s.\n",
					check.Results[0]["LAST_SUCCESSFUL_CONNECT"],
				)
			}
		case "CheckPasswordLifetime":
			var users []map[string]interface{}
			utils.Error("[!] The following users have password lifetime disabled(IS_PASSWORD_LIFETIME_CHECK_ENABLED=FALSE).\n")
			for _, r := range check.Results {
				user := r["USER_NAME"].(string)
				if (isPredefined(user) && strings.HasPrefix(user, "_SYS_")) || strings.HasPrefix(user, "XSSQLCC_AUTO_USER_") {
					continue
				}
				users = append(users, r)
			}
			for _, u := range users {
				fmt.Println("  -", u["USER_NAME"].(string))
			}
		case "SystemPrivileges":
			grantees := make(map[string]entity)
			privileges := make(map[string][]entity)
			utils.Error("[!] Please review the following entities (users/roles) because they might have too high privileges:\n")
			utils.Info("[I] Breakdown per grantee\n")
			//fmt.Println(check.Results)
			for _, r := range check.Results {
				user := r["GRANTEE"].(string)
				grantees[user] = entity{
					Type:       r["GRANTEE_TYPE"].(string),
					Name:       user,
					Privileges: append(grantees[user].Privileges, r["PRIVILEGE"].(string)),
				}
			}
			for k, grantee := range grantees {
				fmt.Printf("  - %s (entity type: %s)\n", k, grantee.Type)
				for _, p := range grantee.Privileges {
					fmt.Println("    - ", p)
				}
				for _, p := range grantee.Privileges {
					privileges[p] = append(privileges[p], grantee)
				}
			}
			utils.Info("[I] Breakdown per privilege\n")
			for privilege, entities := range privileges {
				fmt.Printf("  - %s\n", privilege)
				for _, entity := range entities {
					fmt.Printf("    - %s (type: %s)\n", entity.Name, entity.Type)
				}
			}
		default:
			utils.Error("Unknown check name %s\n", check.Name)
			os.Exit(1)
		}
		fmt.Println("-----------")
		/* for _, r := range check.Results {
			for key, val := range r {
				fmt.Printf("%s: %s\n", key, val)
			}
		} */
	}

}

func newCheck(name, description, link, recommendation, query string, parameters []string) *Check {
	if name == "" || query == "" {
		log.Fatalf("Query creation failed. Name and Query fields required.")
	}
	return &Check{
		Name:           name,
		Description:    description,
		Link:           link,
		Recommendation: recommendation,
		Query:          query,
		Parameters:     parameters,
		Results:        db.Results{},
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
		[]string{},
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
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "SystemPrivileges"
	description = "System privileges authorize database-wide administration commands. The users SYSTEM and _SYS_REPO have all these privileges by default."
	link = "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/45955420940c4e80a1379bc7270cead6.html?locale=en-US#system-privileges"
	recommendation = "System privileges should only ever be granted to users that actually need them. In addition, several system privileges grant powerful permissions, for example, the ability to delete data and to view data unfiltered and should be granted with extra care."
	p := "'" + strings.Join(ADMIN_PRIVILEGES, "', '") + "'"
	stmt := fmt.Sprintf(systemPrivileges, p)
	fmt.Println(stmt)
	AllChecks = append(AllChecks, newCheck(
		name,
		description,
		link,
		recommendation,
		stmt,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
}
