package checks

import (
	"fmt"
	"hana/utils"
	"log"
	"os"
	"strings"
	"time"

	"gopkg.in/agrison/go-tablib.v1"
)

func EvaluateResults() {
	for _, check := range CheckList {
		if strings.HasPrefix(check.Name, "_pre_") {
			continue
		}
		utils.Title("Check: %s\n", check.Name)
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
			preAuditing, err := getCheckByName(fmt.Sprintf("_pre_%s", check.Name))
			if err != nil {
				log.Println(err.Error())
				break
			}
			if len(check.Results) == 0 || (len(check.Results) > 0 && check.Results[0]["COUNT"].(int64) == 0) {
				utils.Error("[!] Auditing disabled. Value of global_auditing_state key, in [audit configuration] section in global.ini file, is not set or FALSE.\n")
			} else {
				utils.Ok("[+] Auditing enabled. Value of global_auditing_state key, in [audit configuration] section in global.ini file, %s \n", check.Results[0]["COUNT"].(int64))
				utils.Info("The total number of auditing policies found is: %d.\n", preAuditing.Results[0]["COUNT"])
			}
		case "AuditingCSV":
			preAuditingCSV, err := getCheckByName(fmt.Sprintf("_pre_%s", check.Name))
			if err != nil {
				log.Println(err.Error())
				break
			}
			if len(check.Results) == 0 && len(preAuditingCSV.Results) == 0 {
				utils.Error("[!] The audit trail target CSV file (CSVTEXTFILE) is not configured.\n")
			} else {
				utils.Ok("[+] Auditing of CSV files is enabled. The following policies have been detected:\n")
				if len(preAuditingCSV.Results) > 0 {
					for _, r := range preAuditingCSV.Results {
						fmt.Printf(
							"  - File: %s, Section: %s, Key: %s, Value: %s\n",
							r["FILE_NAME"].(string),
							r["SECTION"].(string),
							r["KEY"].(string),
							r["VALUE"].(string),
						)
					}
				}
				if len(check.Results) > 0 {
					for _, r := range check.Results {
						fmt.Printf(
							"  - Audit policy name: %s (active: %s), User name: %s\n",
							r["AUDIT_POLICY_NAME"].(string),
							r["IS_AUDIT_POLICY_ACTIVE"].(string),
							r["USER_NAME"].(string),
						)
					}
				}
			}
			utils.Warning("CAVEAT!! To ensure you thoroughly checked the configuration perform the following manual controls.\n")
			fmt.Println("  - The default audit trail target is syslog (SYSLOGPROTOCOL) for the system database. If you are using syslog, ensure that it is installed and configured according to your requirements (for example, for writing the audit trail to a remote server). [https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/5c34ecd355e44aa9af3b3e6de4bbf5c1.html#audit-trail-target%3A-syslog]")
		case "InternalHostnameResolutionSingle":
			if len(check.Results) == 0 {
				utils.Error("[!] In file global.ini there is no listeninterface key in [communication] section.\nNo default value is known, this could lead to unexpected behavior. It is suggested to double check the global.ini configuration file and set listeninterface key to the appropriate value.")
			} else if len(check.Results) == 1 {
				v := check.Results[0]["VALUE"].(string)
				if v == ".local" {
					utils.Ok("In global.ini files, the [communication] listeninterface is set to %s.\n", v)
				} else {
					utils.Error("In global.ini files, the [communication] listeninterface is set to %s.\n", v)
					if v == ".global" {
						utils.Warning("If the listeninterface parameter is set to .global, we strongly recommend that you secure the SAP HANA servers with additional measures such as a firewall and/or TLS/SSL. Otherwise, the internal service ports of the system are exposed and can be used to attack SAP HANA.\n")
					}
				}
			}
			utils.Info("Further information about possible values at: https://help.sap.com/docs/SAP_HANA_PLATFORM/6b94445c94ae495c83a19646e7c3fd56/3fd4912896284029931997903c75d956.html\n")
		case "InternalHostnameResolutionMultiple":
			internal, err := getCheckByName("InternalHostnameResolutionSingle")
			if err != nil {
				log.Println(err.Error())
				break
			}
			if len(internal.Results) == 1 {
				v := internal.Results[0]["VALUE"].(string)
				if v == ".internal" {
					if len(check.Results) > 0 {
						utils.Warning("[-] The following hostname are set:\n")
						for _, r := range check.Results {
							fmt.Printf("  - %s -> %s\n", r["KEY"].(string), r["VALUE"].(string))
						}
					} else {
						utils.Info("Even if the system is configured as multi host (listeninterface in [communication] section is %s) no hostname was found in [internal_hostname_resolution] section\n", v)
					}
				} else {
					utils.Info("The system is not in multi host configuration, listeninterface value in [communication] section is %s\n", v)
				}
			}
		case "HostnameResolutionReplication":
			pre0, err := getCheckByName("_pre_0_HostnameResolutionReplication")
			if err != nil {
				log.Println(err.Error())
				break
			}
			pre1, err := getCheckByName("_pre_1_HostnameResolutionReplication")
			if err != nil {
				log.Println(err.Error())
				break
			}
			if len(pre0.Results) == 1 {
				v := pre0.Results[0]["VALUE"].(string)
				if v == ".global" {
					if len(pre1.Results) > 0 {
						utils.Warning("[-] The following hostname are set:\n")
						for _, r := range pre1.Results {
							fmt.Printf("  - %s -> %s\n", r["KEY"].(string), r["VALUE"].(string))
						}
					} else {
						utils.Info("Even if the system is configured as multi host (listeninterface in [communication] section is %s) no hostname was found in [system_replication_communication] section\n", v)
					}
					if len(check.Results) == 0 {
						utils.Error("[!] No restriction found in key allowed_sender in section [system_replication_communication].\n")
					} else {
						var allowList []string
						for _, v := range check.Results {
							allowList = append(allowList, v["VALUE"].(string))
						}
						if len(allowList) == 1 && allowList[0] == "" {
							break
						}
						if len(allowList) > 0 {
							utils.Info("Communication is restricted to the following hostnames:\n")
							for _, h := range allowList {
								if h == "" {
									continue
								}
								fmt.Printf("  - %s\n", h)
							}
						}
					}
				}
				utils.Warning("If the listeninterface parameter is set to .global, we strongly recommend that you secure the SAP HANA servers with additional measures such as a firewall and/or TLS/SSL. Otherwise, the internal service ports of the system are exposed and can be used to attack SAP HANA.\n")
			}
		case "InstanceSSFSMasterKey":
			if len(check.Results) == 0 {
				utils.Error("[!] Instance SSFS Master Key has never been rotated.\n")
			} else {
				utils.Ok("[+] Instance SSFS Master Key was last rotation time: %s\n", check.Results[0]["VALUE"])
			}
		case "SystemPKISSFSMasterKey":
			if len(check.Results) == 0 {
				utils.Error("[!] System PKI SSFS Master Key has never been rotated.\n")
			} else {
				utils.Ok("[+] System PKI SSFS Master Key was last rotation time: %s\n", check.Results[0]["VALUE"])
			}
		case "PasswordHashMethods":
			if len(check.Results) == 0 ||
				(len(check.Results) == 1 &&
					strings.Contains(strings.ToUpper(fmt.Sprintf("%s", check.Results[0]["VALUE"])), "sha256")) {
				utils.Warning("[!] Legacy and deprecated password storage method in use (SHA256).\n")
			} else if len(check.Results) == 1 && strings.ToUpper(fmt.Sprintf("%s", check.Results[0]["VALUE"])) == "pbkdf2" {
				utils.Warning("[+] All database user passwords are stored using PBKDF2 (Password-Based Key Derivation Function 2)\n")
			}
		case "RootEncryptionKeys":
			for _, record := range check.Results {
				keyVersions := record["VERSIONS"].(int64)
				keyType := record["ROOT_KEY_TYPE"].(string)
				keyCreationDateString := record["CREATION_DATE"].(string)
				keyLastVersionDateString := record["LAST_VERSION_DATE"].(string)
				layout := "2006-01-02 15:04:05"
				keyCreationDate, err := time.Parse(layout, keyCreationDateString)
				if err != nil {
					log.Println(err.Error())
				}
				keyLastVersionDate, _ := time.Parse(layout, keyLastVersionDateString)
				if err != nil {
					log.Println(err.Error())
				}
				if keyVersions == 1 {
					utils.Error("[!] ROOT key of type '%s' was never rotated.\n", keyType)
					utils.Info("\t- Creation date: %s\n", utils.Red(keyCreationDate.Format(layout)))
				} else {
					duration := oneMonth
					if time.Now().After(keyLastVersionDate.Add(duration.Value)) {
						utils.Warning("[!] ROOT key of type '%s' was rotated more than %s ago.\n", keyType, duration.Literal)
						utils.Info("\t- Creation date: %s\n\t- Rotation date: %s\n", keyCreationDate.Format(layout), utils.Yellow(keyLastVersionDate.Format(layout)))
					} else {
						utils.Ok("[+] ROOT key of type '%s' was rotated less than %s ago.\n", keyType, duration.Literal)
						utils.Info("\t- Creation date: %s\n\t- Rotation date: %s\n", keyCreationDate.Format(layout), keyLastVersionDate.Format(layout))
					}
				}
			}
		case "DataAndLogVolumeEncryption":
			var dict = map[string]string{
				"PERSISTENCE": "Data",
				"LOG":         "Log",
				"BACKUP":      "Backup",
			}
			for _, record := range check.Results {
				enabled := false
				scope, ok := record["SCOPE"].(string)
				if !ok {
					log.Printf("Type assertion of %s failed.\n", record["SCOPE"])
				}
				if strings.ToLower(record["IS_ENCRYPTION_ACTIVE"].(string)) == "true" {
					enabled = true
				}
				if !ok {
					log.Printf("Type assertion of %s failed.\n", record["IS_ENCRYPTION_ACTIVE"])
				}
				if enabled {
					utils.Ok("[+] Encryption of %s is active.\n", dict[scope])
				} else {
					utils.Error("[!] Encryption of %s is disabled.\n", dict[scope])
				}
			}
		case "EncryptionKeySAPHANASecureUserStore":
			out := check.Results[0]["stdOut"].(string)
			if strings.Contains(out, "KEY FILE") {
				utils.Ok("[+] Encryption key (SSFS_HDB.KEY) found, Secure User Store is correctly encrypted.\n")
			} else {
				utils.Error("[!] Encryption key (SSFS_HDB.KEY) not found, Secure User Store is not encrypted.\n")
			}
		case "TraceFiles":
			pre0, err := getCheckByName("_pre_0_TraceFiles")
			if err != nil {
				log.Println(err.Error())
				break
			}
			out := check.Results
			if len(pre0.Results) > 0 && len(out) > 0 {
				utils.Warning("[!] Trace files found\n")
				for _, f := range out {
					utils.Info(fmt.Sprintf(
						"%-20s %-20s %-s\n",
						fmt.Sprintf("%-10d byte", f["FILE_SIZE"]),
						f["FILE_MTIME"],
						f["FILE_NAME"],
					))
				}
			} else {
				utils.Ok("[+] Trace files not found\n")
			}
		case "DumpFiles":
			if len(check.Results) > 0 {
				utils.Warning("[!] Dump files found.\n")
				for _, f := range check.Results {
					utils.Info(fmt.Sprintf(
						"%-20s %-20s %-s\n",
						fmt.Sprintf("%-10d byte", f["FILE_SIZE"]),
						f["FILE_MTIME"],
						f["FILE_NAME"],
					))
				}
			} else {
				utils.Ok("[+] Dump files not found\n")
			}
		case "SAMLBasedAuthN":
			if len(check.Results) > 0 {
				utils.Warning("[!] The following SAML or SSL certificates were found.\nPlease review them carefully to avoid authentication issues cross-tenant.\n")
				for _, f := range check.Results {
					utils.Info(fmt.Sprintf(
						"%-20s %-20s %-20s %-s\n",
						f["PSE_ID"],
						f["NAME"],
						f["PURPOSE"],
						f["OWNER_NAME"],
					))
				}
			} else {
				utils.Ok("[+] No SAML or SSL certificates found. Probably authentication is not based on SAML or mTLS\n")
			}
		case "ConfigurationBlacklist":
			ds := tablib.NewDataset([]string{
				"LAYER_NAME",
				"TENANT_NAME",
				"HOST",
				"SECTION",
				"KEY",
				"VALUE",
			})
			if len(check.Results) > 0 {
				utils.Warning("[!] Please review the following configuration blacklist entries in file multidb.ini.\n")
				for _, f := range check.Results {
					ds.AppendValues(
						f["LAYER_NAME"],
						f["TENANT_NAME"],
						f["HOST"],
						f["SECTION"],
						f["KEY"],
						f["VALUE"],
					)
				}
				out := ds.Markdown()
				fmt.Println(out)
			} else {
				log.Fatalln("No configuration found. SAP Hana usually has default configuration. Check it manually. The ran query is: `SELECT * FROM \"PUBLIC\". \"M_INIFILE_CONTENTS\" WHERE FILE_NAME = 'multidb.ini'`")
			}
		case "RestrictedFeatures":
			ds := tablib.NewDataset([]string{
				"NAME",
				"DESCRIPTION",
			})
			if len(check.Results) > 0 {
				utils.Warning("[!] Please review the following customizable functionalities.\n")
				for _, f := range check.Results {
					ds.AppendTagged(
						[]interface{}{
							f["NAME"],
							f["DESCRIPTION"],
						},
						fmt.Sprintf("%s", f["IS_ENABLED"]),
					)
				}
				enabled := ds.Filter("TRUE")
				enabledOutput := ""
				if len(enabled.Dict()) > 0 {
					enabledOutput = enabled.Markdown()
					utils.Info("Enabled features\n")
					fmt.Println(enabledOutput)
				}
				disabled := ds.Filter("FALSE")
				disabledOutput := ""
				if len(disabled.Dict()) > 0 {
					disabledOutput = disabled.Markdown()
					utils.Info("Disabled features\n")
					fmt.Println(disabledOutput)
				}
				if len(disabled.Dict()) == 0 {
					utils.Info("All features are enabled.\n")
				}
				if len(enabled.Dict()) == 0 {
					utils.Info("All features are disabled.\n")
				}
			} else {
				log.Fatalln("No customizable functionalities found. SAP Hana usually has default customizable functionalities. Check it manually. The ran query is: `SELECT * FROM \"PUBLIC\". \"M_CUSTOMIZABLE_FUNCTIONALITIES\"`")
			}
		/* case "TraceFilesSSH":
		out := check.Results[0]["stdOut"].(string)
		pattern := `Trace\s+flags\s*:\s*\(none\s+set\)`
		re := regexp.MustCompile(pattern)
		match := re.MatchString(out)
		if match {
			utils.Ok("[+] Trace option not enabled\n")
		} else {
			utils.Warning("[!] Trace option enabled\n")
			utils.Info("Enabled traces:\n")
			pattern := `(?m)^\s*(.+?)\s+trace\s+:\s+(enabled|disabled)$`
			re := regexp.MustCompile(pattern)

			// Find all matches
			matches := re.FindAllStringSubmatch(out, -1)

			// Extract and print each trace and its status
			for _, match := range matches {
				traceName := strings.TrimSpace(match[1])
				traceStatus := strings.TrimSpace(match[2])
				utils.Info("%s trace: ", traceName)
				if traceStatus == "enabled" {
					fmt.Println(utils.Green(traceStatus))
				} else if traceStatus == "disabled" {
					fmt.Println(utils.Red(traceStatus))
				}
			}
		}
		case "DumpFilesSSH":
			var sshErr *ssh.SSHError
			fmt.Printf("stdOut: %s\n", check.Results[0]["stdOut"])
			fmt.Printf("stdErr: %s\n", check.Results[0]["stdErr"])
			fmt.Printf("err: %s\n", check.Results[0]["err"])
			err := check.Results[0]["err"].(error)
			if err != nil && errors.As(err, &sshErr) {
				fmt.Printf("Error is not nil: %v\n", sshErr)
				if sshErr.Code() == 2 {
					utils.Green("[+] Directory /usr/sap/%s/SYS/global/sapcontrol/snapshots not found.\n", config.Conf.Instance.SID)
				}
			} */
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
		Query,
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
		Query,
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
		Query,
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
		Query,
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
		Query,
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
		Query,
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
		Query,
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
		Query,
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
		Query,
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
		Query,
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
		Query,
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
		Query,
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
		Query,
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
		Query,
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
		Query,
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
		Query,
		name,
		description,
		link,
		recommendation,
		osFsPermissions,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "_pre_Auditing"
	description = "Auditing is disabled by default."
	link = "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/5c34ecd355e44aa9af3b3e6de4bbf5c1.html#auditing"
	recommendation = "Verify whether auditing is required by your security concept, for example to fulfill specific compliance and regulatory requirements."
	CheckList = append(CheckList, newCheck(
		Query,
		name,
		description,
		link,
		recommendation,
		_pre_auditing,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "Auditing"
	description = "Number of auditing policies if auditing is enabled"
	link = "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/5c34ecd355e44aa9af3b3e6de4bbf5c1.html#auditing"
	recommendation = "Verify whether auditing is required by your security concept, for example to fulfill specific compliance and regulatory requirements."
	CheckList = append(CheckList, newCheck(
		Query,
		name,
		description,
		link,
		recommendation,
		auditing,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "_pre_AuditingCSV"
	description = "preparation query"
	link = "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/5c34ecd355e44aa9af3b3e6de4bbf5c1.html#audit-trail-target%3A-csv-text-file"
	recommendation = "Do not configure CSV text file (CSVTEXTFILE) as an audit trail target in a production system as it has severe restrictions."
	CheckList = append(CheckList, newCheck(
		Query,
		name,
		description,
		link,
		recommendation,
		_pre_auditingCSV,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "AuditingCSV"
	description = "The audit trail target CSV text file (CSVTEXTFILE) is not configured by default"
	link = "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/5c34ecd355e44aa9af3b3e6de4bbf5c1.html#audit-trail-target%3A-csv-text-file"
	recommendation = "Do not configure CSV text file (CSVTEXTFILE) as an audit trail target in a production system as it has severe restrictions."
	CheckList = append(CheckList, newCheck(
		Query,
		name,
		description,
		link,
		recommendation,
		auditingCSV,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "InternalHostnameResolutionSingle"
	description = "SAP HANA services use IP addresses to communicate with each other. Host names are mapped to these IP addresses through internal host name resolution, a technique by which the use of specific and/or fast networks can be enforced and communication restricted to a specific network. In single-host systems, SAP HANA services listen on the loopback interface only (IP address 127.0.0.1). In global.ini files, the [communication] listeninterface is set to .local."
	link = "https://help.sap.com/docs/SAP_HANA_COCKPIT/afa922439b204e9caf22c78b6b69e4f2/eccef06eabe545e68d5019bcb6d8e342.html?locale=en-US&version=2.12.0.0#internal-host-name-resolution-in-single-host-system"
	recommendation = "Do not change the default setting."
	CheckList = append(CheckList, newCheck(
		Query,
		name,
		description,
		link,
		recommendation,
		internalHostnameResolutionSingle,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "InternalHostnameResolutionMultiple"
	description = "In a distributed scenario with multiple hosts, the network needs to be configured so that inter-service communication is operational throughout the entire landscape. The default configuration depends on how you installed your system."
	link = "https://help.sap.com/docs/SAP_HANA_COCKPIT/afa922439b204e9caf22c78b6b69e4f2/eccef06eabe545e68d5019bcb6d8e342.html?locale=en-US&version=2.12.0.0#internal-host-name-resolution-in-multiple-host-system"
	recommendation = "Multiple-host systems can run with or without a separate network definition for inter-service communication. The recommended setting depends accordingly. If a separate network is configured for internal communication, the parameter [communication] listeninterface should be set to .internal. If a separate network is not configured for internal communication, the parameter [communication] listeninterface should be set to .global."
	CheckList = append(CheckList, newCheck(
		Query,
		name,
		description,
		link,
		recommendation,
		internalHostnameResolutionMultiple,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "_pre_0_HostnameResolutionReplication"
	description = "preliminary query #1 for hostname resolution replication check"
	link = "https://help.sap.com/docs/SAP_HANA_COCKPIT/afa922439b204e9caf22c78b6b69e4f2/eccef06eabe545e68d5019bcb6d8e342.html?locale=en-US&version=2.12.0.0#host-name-resolution-in-system-replication"
	recommendation = "The recommended setting depends on whether or not a separate network is defined for internal communication. If a separate internal network channel is configured for system replication, the parameter [system_replication_communication] listeninterface parameter should be .internal. If a separate network is not configured for system replication, the parameter [system_replication_communication] listeninterface should be set to .global."
	CheckList = append(CheckList, newCheck(
		Query,
		name,
		description,
		link,
		recommendation,
		_pre_0_hostnameResolutionReplication,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "_pre_1_HostnameResolutionReplication"
	description = "preliminary query #2 for hostname resolution replication check"
	link = "https://help.sap.com/docs/SAP_HANA_COCKPIT/afa922439b204e9caf22c78b6b69e4f2/eccef06eabe545e68d5019bcb6d8e342.html?locale=en-US&version=2.12.0.0#host-name-resolution-in-system-replication"
	recommendation = "The recommended setting depends on whether or not a separate network is defined for internal communication. If a separate internal network channel is configured for system replication, the parameter [system_replication_communication] listeninterface parameter should be .internal. If a separate network is not configured for system replication, the parameter [system_replication_communication] listeninterface should be set to .global."
	CheckList = append(CheckList, newCheck(
		Query,
		name,
		description,
		link,
		recommendation,
		_pre_1_hostnameResolutionReplication,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "HostnameResolutionReplication"
	description = "The parameter [system_replication_communication] listeninterface parameter is set to .global."
	link = "https://help.sap.com/docs/SAP_HANA_COCKPIT/afa922439b204e9caf22c78b6b69e4f2/eccef06eabe545e68d5019bcb6d8e342.html?locale=en-US&version=2.12.0.0#host-name-resolution-in-system-replication"
	recommendation = "The recommended setting depends on whether or not a separate network is defined for internal communication. If a separate internal network channel is configured for system replication, the parameter [system_replication_communication] listeninterface parameter should be .internal. If a separate network is not configured for system replication, the parameter [system_replication_communication] listeninterface should be set to .global."
	CheckList = append(CheckList, newCheck(
		Query,
		name,
		description,
		link,
		recommendation,
		hostnameResolutionReplication,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "InstanceSSFSMasterKey"
	description = "The instance secure store in the file system (SSFS) protects internal root keys in the file system. A unique master key is generated for the instance SSFS in every installation."
	link = "https://help.sap.com/docs/SAP_HANA_COCKPIT/afa922439b204e9caf22c78b6b69e4f2/904911eb0fe54124b10dfaeadb5337ce.html?locale=en-US&version=2.12.0.0#instance-ssfs-master-key"
	recommendation = "If you received your system pre-installed from a hardware or hosting partner, we recommend that you change the master key of the instance SSFS immediately after handover to ensure that it is not known outside of your organization."
	CheckList = append(CheckList, newCheck(
		Query,
		name,
		description,
		link,
		recommendation,
		instanceSSFSMasterKey,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "SystemPKISSFSMasterKey"
	description = "The system public key infrastructure (PKI) SSFS protects the X.509 certificate infrastructure that is used to secure internal TLS/SSL-based communication. A unique master key is generated for the system PKI SSFS in every installation."
	link = "https://help.sap.com/docs/SAP_HANA_COCKPIT/afa922439b204e9caf22c78b6b69e4f2/904911eb0fe54124b10dfaeadb5337ce.html?locale=en-US&version=2.12.0.0#system-pki-ssfs-master-key"
	recommendation = "If you received your system pre-installed from a hardware or hosting partner, we recommend that you change the master key of the instance SSFS immediately after handover to ensure that it is not known outside of your organization."
	CheckList = append(CheckList, newCheck(
		Query,
		name,
		description,
		link,
		recommendation,
		systemPKISSFSMasterKey,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "PasswordHashMethods"
	description = "All database user passwords are stored in salted hash form using PBKDF2 (Password-Based Key Derivation Function 2) and, for downward compatibility, secure hash algorithm SHA-256. The SAP HANA implementation of PBKDF2 uses the SHA-256 secure hash algorithm and 15,000 iterations."
	link = "https://help.sap.com/docs/SAP_HANA_PLATFORM/6b94445c94ae495c83a19646e7c3fd56/b30fda1483b34628802a8d62bd5d39df.html"
	recommendation = "If not strictly required disable hash method SHA-256. The hash method SHA-256 can be disabled by setting the parameter [authentication] password_hash_methods in the global.ini configuration file to pbkdf2. The default value is pbkdf2,sha256."
	CheckList = append(CheckList, newCheck(
		Query,
		name,
		description,
		link,
		recommendation,
		passwordHashMethods,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "RootEncryptionKeys"
	description = "Unique root keys are generated during installation or database creation."
	link = "https://help.sap.com/docs/SAP_HANA_COCKPIT/afa922439b204e9caf22c78b6b69e4f2/904911eb0fe54124b10dfaeadb5337ce.html?locale=en-US&version=2.12.0.0#root-encryption-keys"
	recommendation = "If you received your system pre-installed from a hardware or hosting partner, we recommend that you change all root keys immediately after handover to ensure that they are not known outside of your organization."
	CheckList = append(CheckList, newCheck(
		Query,
		name,
		description,
		link,
		recommendation,
		rootEncryptionKeys,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "DataAndLogVolumeEncryption"
	description = "Data and log volume encryption are not enabled by default."
	link = "https://help.sap.com/docs/SAP_HANA_COCKPIT/afa922439b204e9caf22c78b6b69e4f2/904911eb0fe54124b10dfaeadb5337ce.html?locale=en-US&version=2.12.0.0#data-and-log-volume-encryption"
	recommendation = "We recommend that you enable data and log volume encryption immediately after installation or handover from your hardware or hosting partner, and after you have changed the root encryption keys for both services"
	CheckList = append(CheckList, newCheck(
		Query,
		name,
		description,
		link,
		recommendation,
		dataAndLogVolumeEncryption,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "EncryptionKeySAPHANASecureUserStore"
	description = "The secure user store (hdbuserstore) is a tool installed with the SAP HANA client. It is used to store SAP HANA connection information, including user passwords, securely on clients. Information contained in the SAP HANA secure user store is encrypted using a unique encryption key."
	link = "https://help.sap.com/docs/SAP_HANA_COCKPIT/afa922439b204e9caf22c78b6b69e4f2/904911eb0fe54124b10dfaeadb5337ce.html?locale=en-US&version=2.12.0.0#encryption-key-of-the-sap-hana-secure-user-store-(hdbuserstore)"
	recommendation = "If you are using the current version of the SAP HANA client, there is no need to change the encryption key of the secure user store. However, if you are using an older version of the SAP HANA client, we recommend changing the encryption key after installation of the SAP HANA client."
	CheckList = append(CheckList, newCheck(
		Command,
		name,
		description,
		link,
		recommendation,
		encryptionKeySAPHANASecureUserStore,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "_pre_0_TraceFiles"
	description = "preliminary query #1 for trace files check"
	link = "https://help.sap.com/docs/SAP_HANA_COCKPIT/afa922439b204e9caf22c78b6b69e4f2/9630172f36564ee5ba26c13c054a35e1.html?locale=en-US&version=2.12.0.0#trace-files"
	recommendation = "- Enable tracing to troubleshoot specific problems only and then disable.\n- Exercise caution when setting or changing the trace level. A high trace level may expose certain security-relevant data (for example, database trace level DEBUG or SQL trace level ALL_WITH_RESULTS).\n- Delete trace files that are no longer needed."
	CheckList = append(CheckList, newCheck(
		Query,
		name,
		description,
		link,
		recommendation,
		_pre_0_TraceFiles,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "TraceFiles"
	description = "Basic tracing of activity in database components is enabled by default, with each database service writing to its own trace file. Other traces (for example, SQL trace, expensive statements trace, performance trace) must be explicitly enabled. Users with the system privilege CATALOG READ can read the contents of trace files in the SAP HANA studio. At operating system level, any user in the SAPSYS group can access the trace directory: /usr/sap/<SID>/HDB<instance>/<host>/trace/<db_name>"
	link = "https://help.sap.com/docs/SAP_HANA_COCKPIT/afa922439b204e9caf22c78b6b69e4f2/9630172f36564ee5ba26c13c054a35e1.html?locale=en-US&version=2.12.0.0#trace-files"
	recommendation = "- Enable tracing to troubleshoot specific problems only and then disable.\n- Exercise caution when setting or changing the trace level. A high trace level may expose certain security-relevant data (for example, database trace level DEBUG or SQL trace level ALL_WITH_RESULTS).\n- Delete trace files that are no longer needed."
	CheckList = append(CheckList, newCheck(
		Query,
		name,
		description,
		link,
		recommendation,
		traceFiles,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "DumpFiles"
	description = "The system generates core dump files (for example, crash dump files) automatically. Runtime (RTE) dump files can be triggered explicitly, for example by using the SAP HANA database management console (hdbcons) or as part of a full system information dump (fullSystemInfoDump.py). Dump files are stored in the trace directory and have the same access permissions as other trace files (see above). Runtime dump files created as part of a full system information dump can be retrieved by users with the EXECUTE privilege on the procedure SYS.FULL_SYSTEM_INFO_DUMP_RETRIEVE. At operating system level, any user in the SAPSYS group can access their storage location: /usr/sap/SID/SYS/global/sapcontrol/snapshots"
	link = "https://help.sap.com/docs/hana-cloud-database/sap-hana-cloud-sap-hana-database-security-guide/recommendations-for-trace-and-dump-files#dump-files"
	recommendation = "- Generate runtime dump files to analyze specific error situations only, typically at the request of SAP support.\n- Delete dump files that are no longer needed."
	CheckList = append(CheckList, newCheck(
		Query,
		name,
		description,
		link,
		recommendation,
		dumpFiles,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "SAMLBasedAuthN"
	description = "All tenant databases use the same trust store as the system database for SAML-based user authentication"
	link = "https://help.sap.com/docs/SAP_HANA_COCKPIT/afa922439b204e9caf22c78b6b69e4f2/a6e033bd909948d5b12caeb2ceba20d4.html?version=2.12.0.0#saml-based-user-authentication"
	recommendation = "To prevent users of one tenant database being able to log on to other databases in the system (including the system database) using SAML, create individual certificate collections with the purpose SAML and SSL in every tenant database. In addition, specify a non-existent trust store for every tenant database using the [communication] sslTrustStore property in the global.ini file."
	CheckList = append(CheckList, newCheck(
		Query,
		name,
		description,
		link,
		recommendation,
		SAMLBasedAuthN,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "ConfigurationBlacklist"
	description = "A configuration change blacklist (multidb.ini) is delivered with a default configuration. The parameters contained in the blacklist can only be changed by a system administrator in the system database, not by the administrators of individual tenant databases."
	link = "https://help.sap.com/docs/SAP_HANA_COCKPIT/afa922439b204e9caf22c78b6b69e4f2/a6e033bd909948d5b12caeb2ceba20d4.html?version=2.12.0.0#configuration-blacklist"
	recommendation = "Verify that the parameters included in the multidb.ini file meet your requirements and customize if necessary."
	CheckList = append(CheckList, newCheck(
		Query,
		name,
		description,
		link,
		recommendation,
		configurationBlacklist,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	name = "RestrictedFeatures"
	description = "	To safeguard and/or customize your system, it is possible to disable certain database features that provide direct access to the file system, the network, or other resources, for example import and export operations and backup functions. No features are disabled by default."
	link = "https://help.sap.com/docs/SAP_HANA_COCKPIT/afa922439b204e9caf22c78b6b69e4f2/a6e033bd909948d5b12caeb2ceba20d4.html?version=2.12.0.0#restricted-features"
	recommendation = "Review the list of features that can be disabled and disable those that are not required in your implementation scenario."
	CheckList = append(CheckList, newCheck(
		Query,
		name,
		description,
		link,
		recommendation,
		restrictedFeatures,
		[]string{},
	))
	//////////////////////////////////////////////////////////////////////////////
	/* name = "DumpFilesSSH"
	description = "The system generates core dump files (for example, crash dump files) automatically. Runtime (RTE) dump files can be triggered explicitly, for example by using the SAP HANA database management console (hdbcons) or as part of a full system information dump (fullSystemInfoDump.py). Dump files are stored in the trace directory and have the same access permissions as other trace files (see above). Runtime dump files created as part of a full system information dump can be retrieved by users with the EXECUTE privilege on the procedure SYS.FULL_SYSTEM_INFO_DUMP_RETRIEVE. At operating system level, any user in the SAPSYS group can access their storage location: /usr/sap/SID/SYS/global/sapcontrol/snapshots"
	link = "https://help.sap.com/docs/hana-cloud-database/sap-hana-cloud-sap-hana-database-security-guide/recommendations-for-trace-and-dump-files#dump-files"
	recommendation = "- Generate runtime dump files to analyze specific error situations only, typically at the request of SAP support.\n- Delete dump files that are no longer needed."
	command := fmt.Sprintf(dumpFiles, config.Conf.Instance.SID)
	CheckList = append(CheckList, newCheck(
		Command,
		name,
		description,
		link,
		recommendation,
		command,
		[]string{},
	)) */
}
