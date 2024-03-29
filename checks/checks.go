package checks

import (
	"fmt"
	"hana/db"
	"hana/utils"
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
	if len(check.Parameters) > 1 {
		utils.Error("We aren't ready yet to prepare statements w/ mutiple parameters :[")
		os.Exit(1)
	}
	var res db.Results
	for _, p := range check.Parameters {
		stmt := fmt.Sprintf(check.Query, p)
		res = executeQuery(stmt)
	}
	check.Results = res
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
			if len(check.Results) > 0 {
				privileges := make(map[string][]entity)
				utils.Error("[!] Please review the following entities (users/roles) because they might have too high privileges:\n")
				utils.Info("[I] Breakdown per grantee\n")
				grantees := check.listGrantees()
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
			} else {
				utils.Ok("[+] No privilege was found to be reviewed.\n")
			}
		case "CriticalCombinations":
			users := make(map[string]entity)
			for _, r := range check.Results {
				user := r["USER_NAME"].(string)
				if user == "SYSTEM" || user == "_SYS_REPO" {
					continue
				}
				users[user] = entity{
					Name:       user,
					Privileges: append(users[user].Privileges, r["PRIVILEGE"].(string)),
				}
			}
			issues := make(map[string]entity)
			for _, u := range users {
				for _, couple := range DANGEROUS_COMBO {
					if subslice(couple, u.Privileges) {
						issues[u.Name] = u
					}
				}
			}
			if len(issues) > 0 {
				utils.Error("[!] The following users have dangerous privileges combinations.\n")
				var printed []string
				for _, i := range issues {
					fmt.Println("  - ", i.Name)
					for _, p := range i.Privileges {
						for _, couple := range DANGEROUS_COMBO {
							if contains(couple, p) {
								fmt.Printf("    - %s\n", utils.Red(p))
								printed = append(printed, p)
								break
							}
						}
					}
					notPrinted := difference(i.Privileges, printed)
					for _, p := range notPrinted {
						fmt.Printf("    - %s\n", p)
					}
				}
			} else {
				utils.Ok("[+] No dangerous privilege combinations found.\n")
			}
		case "SystemPrivilegeDataAdmin", "SystemPrivilegeDevelopment", "AnalyticPrivilege", "DebugPrivilege":
			if len(check.Results) > 0 {
				utils.Error("[!] The following users/roles have %s privilege:\n", check.Parameters[0])
				grantees := check.listGrantees()
				printGrantees(grantees)
			} else {
				utils.Ok("[+] No user/role has %s privilege.\n", check.Parameters[0])
			}
		case "PredefinedCatalogRoleContentAdmin", "PredefinedCatalogRoleModeling", "PredefinedCatalogRoleSAPSupport":
			if len(check.Results) > 0 {
				utils.Error("[!] The following users/roles have %s role:\n", check.Parameters[0])
				grantees := make(map[string]entity)
				for _, r := range check.Results {
					user := r["GRANTEE"].(string)
					grantees[user] = entity{
						Type:       r["GRANTEE_TYPE"].(string),
						Name:       user,
						Privileges: append(grantees[user].Privileges, r["ROLE_NAME"].(string)),
					}
				}
				printGrantees(grantees)
			} else {
				utils.Ok("[+] No user/role has %s role.\n", check.Parameters[0])
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

func init() {
	getAllUsers()
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
	AllChecks = append(AllChecks, newCheck(
		name,
		description,
		link,
		recommendation,
		stmt,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "CriticalCombinations"
	description = "System privileges authorize database-wide administration commands. The users SYSTEM and _SYS_REPO have all these privileges by default."
	link = "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/45955420940c4e80a1379bc7270cead6.html?locale=en-US#system-privileges"
	recommendation = "System privileges should only ever be granted to users that actually need them. In addition, several system privileges grant powerful permissions, for example, the ability to delete data and to view data unfiltered and should be granted with extra care."
	p = "USER_NAME = '" + strings.Join(userNames, "' OR USER_NAME = '") + "'"
	stmt = fmt.Sprintf(criticalCombinations, p)
	//fmt.Println(stmt)
	AllChecks = append(AllChecks, newCheck(
		name,
		description,
		link,
		recommendation,
		stmt,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "SystemPrivilegeDataAdmin"
	description = "The system privilege DATA ADMIN is a powerful privilege. It authorizes a user to execute all data definition language (DDL) commands in the SAP HANA database. Only the users SYSTEM and _SYS_REPO have this privilege by default."
	link = "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/45955420940c4e80a1379bc7270cead6.html?locale=en-US#system-privilege%3A-data-admin"
	recommendation = "No user or role in a production database should have this privilege."
	AllChecks = append(AllChecks, newCheck(
		name,
		description,
		link,
		recommendation,
		dataAdmin,
		[]string{"DATA ADMIN"},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "SystemPrivilegeDevelopment"
	description = "The system privilege DEVELOPMENT authorizes some internal ALTER SYSTEM commands. By default, only the users SYSTEM and _SYS_REPO have this privilege."
	link = "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/45955420940c4e80a1379bc7270cead6.html?locale=en-US#system-privilege%3A-development"
	recommendation = "No user or role in a production database should have this privilege."
	AllChecks = append(AllChecks, newCheck(
		name,
		description,
		link,
		recommendation,
		dataAdmin,
		[]string{"DEVELOPMENT"},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "AnalyticPrivilege"
	description = "The predefined analytic privilege _SYS_BI_CP_ALL potentially allows a user to access all the data in activated views that are protected by XML-based analytic privileges, regardless of any other XML-based analytic privileges that apply. Only the predefined roles CONTENT ADMIN and MODELING have the analytic privilege _SYS_BI_CP_ALL by default. By default, only the user SYSTEM has these roles."
	link = "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/45955420940c4e80a1379bc7270cead6.html?locale=en-US#analytic-privilege%3A-_sys_bi_cp_all"
	recommendation = "Do not grant this privilege to any user or role in a production database."
	AllChecks = append(AllChecks, newCheck(
		name,
		description,
		link,
		recommendation,
		analyticPrivilege,
		[]string{"_SYS_BI_CP_ALL"},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "DebugPrivilege"
	description = "No user has debug privileges"
	link = "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/45955420940c4e80a1379bc7270cead6.html?locale=en-US#debug-privileges"
	recommendation = "The privileges DEBUG and ATTACH DEBUGGER should not be assigned to any user for any object in production systems."
	AllChecks = append(AllChecks, newCheck(
		name,
		description,
		link,
		recommendation,
		debugPrivilege,
		[]string{"DEBUG"},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "PredefinedCatalogRoleContentAdmin"
	description = "The role CONTENT_ADMIN contains all privileges required for working with information models in the repository of the SAP HANA database. The user SYSTEM has the role CONTENT_ADMIN by default."
	link = "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/45955420940c4e80a1379bc7270cead6.html?locale=en-US#predefined-catalog-role-content_admin"
	recommendation = "Only the database user used to perform system updates should have the role CONTENT_ADMIN. Otherwise do not grant this role to users, particularly in production databases. It should be used as a role template only."
	AllChecks = append(AllChecks, newCheck(
		name,
		description,
		link,
		recommendation,
		predefinedCatalogRole,
		[]string{"CONTENT_ADMIN"},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "PredefinedCatalogRoleModeling"
	description = "The role MODELING contains the predefined analytic privilege _SYS_BI_CP_ALL, which potentially allows a user to access all the data in activated views that are protected by XML-based analytic privileges, regardless of any other XML-based analytic privileges that apply. The user SYSTEM has the role MODELING by default."
	link = "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/45955420940c4e80a1379bc7270cead6.html?version=2.0.05&locale=en-US#predefined-catalog-role-modeling"
	recommendation = "Do not grant this role to users, particularly in production databases. It should be used as a role template only."
	AllChecks = append(AllChecks, newCheck(
		name,
		description,
		link,
		recommendation,
		predefinedCatalogRole,
		[]string{"MODELING"},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "PredefinedCatalogRoleSAPSupport"
	description = "The role MODELING contains the predefined analytic privilege _SYS_BI_CP_ALL, which potentially allows a user to access all the data in activated views that are protected by XML-based analytic privileges, regardless of any other XML-based analytic privileges that apply. The user SYSTEM has the role MODELING by default."
	link = "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/45955420940c4e80a1379bc7270cead6.html?version=2.0.05&locale=en-US#predefined-catalog-role-modeling"
	recommendation = "Do not grant this role to users, particularly in production databases. It should be used as a role template only."
	AllChecks = append(AllChecks, newCheck(
		name,
		description,
		link,
		recommendation,
		predefinedCatalogRoleSAPSupport,
		[]string{"SAP_INTERNAL_HANA_SUPPORT"},
	))
}
