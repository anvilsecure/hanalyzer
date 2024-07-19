package checks

import (
	"fmt"
	"hana/logger"
	"hana/utils"
	"log"
	"os"
	"strings"
	"time"

	"gopkg.in/agrison/go-tablib.v1"
)

var (
	SkippedChecks []*Check
)

func EvaluateResults(checkType CheckType) {
	for _, check := range CheckList {
		if check.Type == QueryType {
			if strings.HasPrefix(check.Name, "_pre_") {
				continue
			}
			utils.Title("Check: %s\n", check.Name)
			switch check.Name {
			case "CheckSystemUser":
				if check.checkEmptyResult() {
					check.Error = fmt.Errorf("Possible error: no user found. Please check it manually.\n")
				} else {
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
				}
			case "CheckPasswordLifetime":
				var users []map[string]interface{}
				if check.checkEmptyResult() {
					utils.Ok("[+] No user found with password lifetime disabled.\n")
				} else {
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
				}
			case "SystemPrivileges":
				if len(check.Results) > 0 {
					privileges := make(map[string][]entity)
					utils.Error("[!] Please review the following entities (users/roles) because they might have too high privileges:\n")
					utils.Info("[I] Breakdown per grantee\n")
					grantees, err := check.listGrantees()
					if err != nil {
						check.Error = err
						break
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
					grantees, err := check.listGrantees()
					if err != nil {
						check.Error = err
						break
					}
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
			default:
				logger.Log.Errorf("Unknown check name %s\n", check.Name)
				os.Exit(1)
			}
			fmt.Println("-----------")
		} else if check.Type == SSHType {
			utils.Title("Check: %s\n", check.Name)
			switch check.Name {
			case "EncryptionKeySAPHANASecureUserStore":
				out := check.Results[0]["stdOut"].(string)
				if strings.Contains(out, "KEY FILE") {
					utils.Ok("[+] Encryption key (SSFS_HDB.KEY) found, Secure User Store is correctly encrypted.\n")
				} else {
					utils.Error("[!] Encryption key (SSFS_HDB.KEY) not found, Secure User Store is not encrypted.\n")
				}
			default:
				logger.Log.Errorf("Unknown check name %s\n", check.Name)
				os.Exit(1)
			}
			fmt.Println("-----------")
		}
	}

}
