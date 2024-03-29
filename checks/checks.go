package checks

import (
	"fmt"
	"hana/utils"
	"log"
	"os"
	"strings"
)

func EvaluateResults() {
	for _, check := range CheckList {
		if strings.HasPrefix(check.Name, "_pre_") {
			continue
		}
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
		case "PredefinedCatalogRoleContentAdmin", "PredefinedCatalogRoleModeling", "PredefinedCatalogRoleSAPSupport", "PredefinedCatalogRepositoryRoles":
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
		case "UserParameterClient":
			preCheckClient, err := getCheckByName(fmt.Sprintf("_pre_%s", check.Name))
			if err != nil {
				log.Println(err.Error())
				break
			}
			if len(preCheckClient.Results) == 0 {
				utils.Ok("[+] secure_client_parameter in [authorization] section in global.ini is not set.\n")
			} else {
				value := preCheckClient.Results[0]["VALUE"].(string)
				if value == "true" {
					utils.Ok("[!] secure_client_parameter in [authorization] section in global.ini is set to true.\n")
				} else {
					utils.Error("[!] secure_client_parameter in [authorization] section in global.ini is set to false\n")
				}
			}
			if len(check.Results) > 0 {
				utils.Error("[!] Please review the following entities (users/roles) because they can change CLIENT user parameter:\n")
				for _, r := range check.Results {
					fmt.Printf("  - %s (type: %s)\n", r["GRANTEE"], r["GRANTEE_TYPE"])
				}
			} else {
				utils.Ok("[+] No user/role can change the CLIENT user parameter.\n")
			}
		case "OSFSPermissions":
			preCheckOS, err := getCheckByName(fmt.Sprintf("_pre_%s", check.Name))
			if err != nil {
				log.Println(err.Error())
				break
			}
			if len(preCheckOS.Results) == 0 {
				utils.Error("[!] file_security in [import_export] section of indexserver.ini not set.\n")
			} else {
				value := preCheckOS.Results[0]["VALUE"].(string)
				if value == "medium" || value == "high" {
					utils.Ok("[+] file_security set to %s value for import/export in indexserver.ini.\n", strings.ToUpper(value))
				} else {
					utils.Error("[!] file_security set to LOW value for import/export in indexserver.ini.\n")
				}
			}
			if len(check.Results) > 0 {
				grantees := make(map[string]entity)
				utils.Error("[!] Please review the following entities (users/roles) because they have IMPORT/EXPORT privileges.\n")
				for _, r := range check.Results {
					grantee := r["GRANTEE"].(string)
					grantees[grantee] = entity{
						Type:       r["GRANTEE_TYPE"].(string),
						Name:       grantee,
						Privileges: append(grantees[grantee].Privileges, r["PRIVILEGE"].(string)),
					}
				}
				for _, g := range grantees {
					fmt.Printf("  - %s (type: %s): %s\n", g.Name, g.Type, strings.Join(g.Privileges, "/"))
				}
			} else {
				utils.Ok("[+] No user/role have IMPORT/EXPORT privileges.\n")
			}
			utils.Warning("CAVEAT!! To ensure you thoroughly checked the configuration perform the following manual controls.\n")
			fmt.Println("  - Only operating system (OS) users that are needed for operating SAP HANA exist on the SAP HANA system, that is: sapadm, <sid>adm, and <sid>crypt. Ensure that no additional unnecessary users exist. [https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/1bea52d12332472cb4a7658300241ce8.html#operating-system-users]")
			fmt.Println("  - You can verify the permissions of directories in the file system using the SAP HANA database lifecycle manager (HDBLCM) resident program with installation parameter check_installation. [https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/1bea52d12332472cb4a7658300241ce8.html#os-file-system-permissions]")
			fmt.Println("  - OS security patches are not installed by default. Install them for you OS as soon as they become available. [https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/1bea52d12332472cb4a7658300241ce8.html#os-security-patches]")
			fmt.Println("  - Check sudo configuration. [https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/1bea52d12332472cb4a7658300241ce8.html#os-sudo-configuration]")
		case "Auditing":

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
	CheckList = append(CheckList, newCheck(
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
	CheckList = append(CheckList, newCheck(
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
	CheckList = append(CheckList, newCheck(
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
	CheckList = append(CheckList, newCheck(
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
	CheckList = append(CheckList, newCheck(
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
	CheckList = append(CheckList, newCheck(
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
	CheckList = append(CheckList, newCheck(
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
	CheckList = append(CheckList, newCheck(
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
	CheckList = append(CheckList, newCheck(
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
	CheckList = append(CheckList, newCheck(
		name,
		description,
		link,
		recommendation,
		predefinedCatalogRole,
		[]string{"MODELING"},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "PredefinedCatalogRoleSAPSupport"
	description = "The role SAP_INTERNAL_HANA_SUPPORT contains system privileges and object privileges that allow access to certain low-level internal system views needed by SAP HANA development support in support situations. No user has the role SAP_INTERNAL_HANA_SUPPORT by default."
	link = "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/45955420940c4e80a1379bc7270cead6.html?version=2.0.05&locale=en-US#predefined-catalog-role-sap_internal_hana_support"
	recommendation = "This role should only be granted to SAP HANA development support users for their support activities."
	CheckList = append(CheckList, newCheck(
		name,
		description,
		link,
		recommendation,
		predefinedCatalogRoleGeneral,
		[]string{"SAP_INTERNAL_HANA_SUPPORT"},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "PredefinedCatalogRepositoryRoles"
	description = "SAP HANA is delivered with a set of preinstalled software components implemented as SAP HANA Web applications, libraries, and configuration data. The privileges required to use these components are contained within repository roles delivered with the component itself. The standard user _SYS_REPO automatically has all of these roles. Some may also be granted automatically to the standard user SYSTEM to enable tools such as the SAP HANA cockpit to be used immediately after installation."
	link = "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/45955420940c4e80a1379bc7270cead6.html?version=2.0.05&locale=en-US#predefined-repository-roles"
	recommendation = "As repository roles can change when a new version of the package is deployed, either do not use them directly but instead as a template for creating your own roles, or have a regular review process in place to verify that they still contain only privileges that are in line with your organization's security policy. Furthermore, if repository package privileges are granted by a role, we recommend that these privileges be restricted to your organization's packages rather than the complete repository. Therefore, for each package privilege (REPO.*) that occurs in a role template and is granted on .REPO_PACKAGE_ROOT, check whether the privilege can and should be granted to a single package or a small number of specific packages rather than the full repository."
	CheckList = append(CheckList, newCheck(
		name,
		description,
		link,
		recommendation,
		predefinedCatalogRoleGeneral,
		[]string{"sap.hana.xs.admin.roles::HTTPDestAdministrator"},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "_pre_UserParameterClient"
	description = "this check is only performed to support UserParameterClient_1"
	link = "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/45955420940c4e80a1379bc7270cead6.html?version=2.0.05&locale=en-US#user-parameter-client"
	recommendation = "Prevent named users from changing the CLIENT user parameter themselves but allow technical users to do so in their sessions and/or queries."
	CheckList = append(CheckList, newCheck(
		name,
		description,
		link,
		recommendation,
		_pre_userParameterClient,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "UserParameterClient"
	description = "The CLIENT user parameter can be used to authorize named users in SAP HANA. Only a user with the USER ADMIN system privilege can change the value of the CLIENT parameter already assigned to other users. However, at runtime, any user can assign an arbitrary value to the CLIENT parameter either by setting the corresponding session variable or passing the parameter via placeholder in a query. While this is the desired behavior for technical users that work with multiple clients such as SAP Business Warehouse, S/4 HANA, or SAP Business Suite, it is problematic in named user scenarios if the CLIENT parameter is used to authorize access to data and not only to perform data filtering."
	link = "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/45955420940c4e80a1379bc7270cead6.html?version=2.0.05&locale=en-US#user-parameter-client"
	recommendation = "Prevent named users from changing the CLIENT user parameter themselves but allow technical users to do so in their sessions and/or queries."
	CheckList = append(CheckList, newCheck(
		name,
		description,
		link,
		recommendation,
		userParameterClient,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "_pre_OSFSPermissions"
	description = "The access permission of files exported to the SAP HANA server can be configured using the [import_export] file_security parameter in the indexserver.ini configuration file. The default permission set is 640 ([import_export] file_security=medium)."
	link = "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/1bea52d12332472cb4a7658300241ce8.html#os-file-system-permissions"
	recommendation = "Do not change default access permission of exported files. In addition, ensure that only a limited number of database users have the system privilege IMPORT and EXPORT."
	CheckList = append(CheckList, newCheck(
		name,
		description,
		link,
		recommendation,
		_pre_osFsPermissions,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "OSFSPermissions"
	description = "The access permission of files exported to the SAP HANA server can be configured using the [import_export] file_security parameter in the indexserver.ini configuration file. Three security levels available: high (600), medium (644, default one), and low (664)."
	link = "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/1bea52d12332472cb4a7658300241ce8.html#os-file-system-permissions"
	recommendation = "Do not change default access permission of exported files. In addition, ensure that only a limited number of database users have the system privilege IMPORT and EXPORT."
	CheckList = append(CheckList, newCheck(
		name,
		description,
		link,
		recommendation,
		osFsPermissions,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "Auditing"
	description = "Auditing is disabled by default."
	link = "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/5c34ecd355e44aa9af3b3e6de4bbf5c1.html#auditing"
	recommendation = "Verify whether auditing is required by your security concept, for example to fulfill specific compliance and regulatory requirements."
	CheckList = append(CheckList, newCheck(
		name,
		description,
		link,
		recommendation,
		auditing,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
}
