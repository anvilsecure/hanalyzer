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
		var message, info, caveat string
		var affectedResources []interface{}
		if check.Error != nil {
			logger.Log.Warnf("error during execution of check \"%s\": %s", check.Name, check.Error.Error())
			continue
		}
		if check.Type == QueryType {
			if strings.HasPrefix(check.Name, "_pre_") {
				continue
			}
			utils.Title("Check: %s\n", check.Name)
			switch check.Name {
			case "CheckSystemUser": // output: DONE
				if check.checkEmptyResult() {
					check.Error = fmt.Errorf("possible error: no user found. Please check it manually")
				} else {
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
						check.Out = message
						check.Info = info
						check.IssuesPresent = false
						check.AffectedResources = nil
					} else {
						message = fmt.Sprintf(
							"[!] User SYSTEM is ACTIVE (USER_DEACTIVATED=%s).\n",
							check.Results[0]["USER_DEACTIVATED"],
						)
						info = fmt.Sprintf(
							"Last successful connection was in date %s.",
							check.Results[0]["LAST_SUCCESSFUL_CONNECT"],
						)
						check.Out = message
						check.Info = info
						check.IssuesPresent = true
						check.AffectedResources = append(check.AffectedResources, "SYSTEM")
					}
				}
			case "CheckPasswordLifetime": // output: DONE
				var users []map[string]interface{}
				if check.checkEmptyResult() {
					message = "[+] No user found with password lifetime disabled."
					check.Out = message
					check.IssuesPresent = false
					check.AffectedResources = nil
				} else {
					message = "[!] The following users have password lifetime disabled(IS_PASSWORD_LIFETIME_CHECK_ENABLED=FALSE).\n"
					for _, r := range check.Results {
						user := r["USER_NAME"].(string)
						if (isPredefined(user) && strings.HasPrefix(user, "_SYS_")) || strings.HasPrefix(user, "XSSQLCC_AUTO_USER_") {
							continue
						}
						users = append(users, r)
						affectedResources = append(affectedResources, user)
					}
					for _, u := range users {
						info += fmt.Sprintf("  - %s\n", u["USER_NAME"].(string))
					}
					check.Out = message
					check.IssuesPresent = true
					check.AffectedResources = affectedResources
				}
			case "SystemPrivileges": // output: DONE
				var affectedResources = []struct {
					Entity     string   `json:"Entity"`
					EntityType string   `json:"EntityType"`
					Privileges []string `json:"Privileges"`
				}{}
				if len(check.Results) > 0 {
					grantees, err := check.listGrantees()
					if err != nil {
						check.Error = err
						break
					}
					privileges := make(map[string][]entity)
					message = "[!] Found entities (users/roles) that might have too high privileges.\n"
					info = "[I] Breakdown per grantee\n"
					for k, grantee := range grantees {
						affectedResources = append(affectedResources, struct {
							Entity     string   "json:\"Entity\""
							EntityType string   "json:\"EntityType\""
							Privileges []string "json:\"Privileges\""
						}{
							Entity:     grantee.Name,
							EntityType: grantee.Type,
							Privileges: grantee.Privileges,
						})
						info += fmt.Sprintf("  - %s (entity type: %s)\n", k, grantee.Type)
						for _, p := range grantee.Privileges {
							info += fmt.Sprintf("    - %s\n", p)
						}
						for _, p := range grantee.Privileges {
							privileges[p] = append(privileges[p], grantee)
						}
					}
					check.AffectedResources = append(check.AffectedResources, affectedResources)
					check.Out = "[!] Found entities (users/roles) that might have too high privileges.\n"
					check.Info = "[I] Breakdown per grantee"
					check.IssuesPresent = true

					info += "[I] Breakdown per privilege\n"
					for privilege, entities := range privileges {
						info += fmt.Sprintf("  - %s\n", privilege)
						for _, entity := range entities {
							info += fmt.Sprintf("    - %s (type: %s)\n", entity.Name, entity.Type)
						}
					}
				} else {
					message = "[+] No privilege was found to be reviewed.\n"
					check.Out = message
					check.IssuesPresent = false
					check.AffectedResources = nil
				}
			case "CriticalCombinations": // output: DONE
				entities := make(map[string]entity)
				for _, result := range check.Results {
					user := result["USER_NAME"].(string)
					if user == "SYSTEM" || user == "_SYS_REPO" {
						continue
					}
					entities[user] = entity{
						Name:       user,
						Type:       "user",
						Privileges: append(entities[user].Privileges, result["PRIVILEGE"].(string)),
					}
				}
				issues := make(map[string]entity)
				for _, entity := range entities {
					for _, couple := range DANGEROUS_COMBO {
						if subslice(couple, entity.Privileges) {
							issues[entity.Name] = entity
						}
					}
				}
				if len(issues) > 0 {
					message = "[!] Found users that might have dangerous privileges combinations.\n"
					var printed []string
					for _, user := range issues {
						var affectedResource = struct {
							Entity     string   "json:\"Entity\""
							EntityType string   "json:\"EntityType\""
							Privileges []string "json:\"Privileges\""
						}{
							Entity:     user.Name,
							EntityType: user.Type,
						}
						info += fmt.Sprintf("  - %s\n", user.Name)
						for _, privilege := range user.Privileges {
							for _, couple := range DANGEROUS_COMBO {
								if contains(couple, privilege) {
									info += fmt.Sprintf("    - %s\n", utils.Red(privilege))
									printed = append(printed, privilege)
									break
								}
							}
							affectedResource.Privileges = printed
						}
						notPrinted := difference(user.Privileges, printed)
						for _, p := range notPrinted {
							info += fmt.Sprintf("    - %s\n", p)
						}
						check.AffectedResources = append(check.AffectedResources, affectedResource)
					}
					check.Out = message
					check.IssuesPresent = true
				} else {
					message = "[+] No dangerous privilege combinations found.\n"
					check.Out = message
					check.IssuesPresent = false
					check.AffectedResources = nil
				}
			case "SystemPrivilegeDataAdmin", "SystemPrivilegeDevelopment", "AnalyticPrivilege", "DebugPrivilege": // output: DONE
				privilege := check.Parameters[0]
				if len(check.Results) > 0 {
					message = fmt.Sprintf("[!] Found users/roles that have %s privilege.\n", privilege)
					grantees, err := check.listGrantees()
					if err != nil {
						check.Error = err
						break
					}
					for _, entity := range grantees {
						check.AffectedResources = append(check.AffectedResources, struct {
							Entity     string   `json:"Entity"`
							EntityType string   `json:"EntityType"`
							Privileges []string `json:"Privileges"`
						}{
							Entity:     entity.Name,
							EntityType: entity.Type,
							Privileges: entity.Privileges,
						})
					}
					info += printGrantees(grantees)
					check.Out = message
					check.IssuesPresent = true
				} else {
					message = fmt.Sprintf("[+] No user/role has %s privilege.", privilege)
					check.Out = message
					check.IssuesPresent = false
					check.AffectedResources = nil
				}
			case "PredefinedCatalogRoleContentAdmin", "PredefinedCatalogRoleModeling", "PredefinedCatalogRoleSAPSupport", "PredefinedCatalogRepositoryRoles": // output: DONE
				if len(check.Results) > 0 {
					message = fmt.Sprintf("[!] Found users/roles that have %s role.\n", check.Parameters[0])
					grantees := make(map[string]entity)
					for _, r := range check.Results {
						user := r["GRANTEE"].(string)
						grantees[user] = entity{
							Type:       r["GRANTEE_TYPE"].(string),
							Name:       user,
							Privileges: append(grantees[user].Privileges, r["ROLE_NAME"].(string)),
						}
					}
					for _, entity := range grantees {
						check.AffectedResources = append(check.AffectedResources, struct {
							Entity     string   `json:"Entity"`
							EntityType string   `json:"EntityType"`
							Privileges []string `json:"Privileges"`
						}{
							Entity:     entity.Name,
							EntityType: entity.Type,
							Privileges: entity.Privileges,
						})
					}
					info += printGrantees(grantees)
					check.Out = message
					check.IssuesPresent = true
				} else {
					message = fmt.Sprintf("[+] No user/role has %s role.", check.Parameters[0])
					check.Out = message
					check.IssuesPresent = false
					check.AffectedResources = nil
				}
			case "UserParameterClient": // output: DONE
				preCheckClient, err := getCheckByName(fmt.Sprintf("_pre_%s", check.Name))
				if err != nil {
					logger.Log.Error(err.Error())
					check.Error = err
					break
				}
				if len(preCheckClient.Results) == 0 {
					message = "[!] secure_client_parameter in [authorization] section in global.ini is not set.\n"
					check.IssuesPresent = true
				} else {
					value := preCheckClient.Results[0]["VALUE"].(string)
					if value == "true" {
						message += "[+] secure_client_parameter in [authorization] section in global.ini is set to true.\n"
						check.IssuesPresent = false
					} else {
						message += "[!] secure_client_parameter in [authorization] section in global.ini is set to false.\n"
						check.IssuesPresent = true
					}
				}
				if len(check.Results) > 0 {
					grantees, err := check.listGrantees()
					if err != nil {
						check.Error = err
						break
					}
					message += "[!] Found entities (users/roles) with the permission to change CLIENT user parameter.\n"
					for _, entity := range grantees {
						info += fmt.Sprintf("  - %s (type: %s)\n", entity.Name, entity.Type)
						check.AffectedResources = append(check.AffectedResources, struct {
							Entity     string   `json:"Entity"`
							EntityType string   `json:"EntityType"`
							Privileges []string `json:"Privileges"`
						}{
							Entity:     entity.Name,
							EntityType: entity.Type,
							Privileges: entity.Privileges,
						})
					}
					check.Out = message
					check.IssuesPresent = true
				} else {
					info += "[+] No user/role can change the CLIENT user parameter."
					check.Out = message
					check.Info = info
					check.AffectedResources = nil
				}
			case "OSFSPermissions": // output: DONE
				preCheckOS, err := getCheckByName(fmt.Sprintf("_pre_%s", check.Name))
				if err != nil {
					logger.Log.Error(err.Error())
					check.Error = err
					break
				}
				if len(preCheckOS.Results) == 0 {
					message = "[!] file_security in [import_export] section of indexserver.ini not set.\n"
					check.IssuesPresent = true
				} else {
					value := preCheckOS.Results[0]["VALUE"].(string)
					if value == "medium" || value == "high" {
						message = fmt.Sprintf("[+] file_security set to %s value for import/export in indexserver.ini.\n", strings.ToUpper(value))
						check.IssuesPresent = false
					} else {
						message = "[!] file_security set to LOW value for import/export in indexserver.ini.\n"
						check.IssuesPresent = true
					}
				}
				if len(check.Results) > 0 {
					message += "[!] Found entities (users/roles) that have IMPORT/EXPORT privileges.\n"
					grantees, err := check.listGrantees()
					if err != nil {
						check.Error = err
						break
					}
					for _, entity := range grantees {
						info += fmt.Sprintf("  - %s (type: %s): %s\n", entity.Name, entity.Type, strings.Join(entity.Privileges, "/"))
						check.AffectedResources = append(check.AffectedResources, struct {
							Entity     string   `json:"Entity"`
							EntityType string   `json:"EntityType"`
							Privileges []string `json:"Privileges"`
						}{
							Entity:     entity.Name,
							EntityType: entity.Type,
							Privileges: entity.Privileges,
						})
					}
					check.Out = message
					check.IssuesPresent = true
				} else {
					message = "[+] No user/role have IMPORT/EXPORT privileges.\n"
					check.Out = message
					check.IssuesPresent = false
					check.AffectedResources = nil
				}
				check.Caveat = "\nCAVEAT!! To ensure you thoroughly checked the configuration perform the following manual controls.\n  - Only operating system (OS) users that are needed for operating SAP HANA exist on the SAP HANA system, that is: sapadm, <sid>adm, and <sid>crypt. Ensure that no additional unnecessary users exist. [https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/1bea52d12332472cb4a7658300241ce8.html#operating-system-users]\n  - You can verify the permissions of directories in the file system using the SAP HANA database lifecycle manager (HDBLCM) resident program with installation parameter check_installation. [https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/1bea52d12332472cb4a7658300241ce8.html#os-file-system-permissions]\n  - OS security patches are not installed by default. Install them for you OS as soon as they become available. [https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/1bea52d12332472cb4a7658300241ce8.html#os-security-patches]\n  - Check sudo configuration. [https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/1bea52d12332472cb4a7658300241ce8.html#os-sudo-configuration]\n"
			case "Auditing": // output: DONE
				preAuditing, err := getCheckByName(fmt.Sprintf("_pre_%s", check.Name))
				if err != nil {
					logger.Log.Error(err.Error())
					break
				}
				if len(check.Results) == 0 || (len(check.Results) > 0 && check.Results[0]["COUNT"].(int64) == 0) {
					message = "[!] Auditing disabled. Value of global_auditing_state key, in [audit configuration] section in global.ini file, is not set or FALSE.\n"
					check.IssuesPresent = true
				} else {
					message = fmt.Sprintf("[+] Auditing enabled. Value of global_auditing_state key, in [audit configuration] section in global.ini file, %d \n", check.Results[0]["COUNT"].(int64))
					check.IssuesPresent = false
					info = fmt.Sprintf("The total number of auditing policies found is: %d.\n", preAuditing.Results[0]["COUNT"])
				}
				check.Out = message
				check.Info = info
				check.AffectedResources = nil
			case "AuditingCSV": // output: DONE
				var affectedResources = []struct {
					Resources struct {
						ConfigurationFiles []struct {
							FileName string `json:"FileName"`
							Section  string `json:"Section"`
							Key      string `json:"Key"`
							Value    string `json:"Value"`
						} `json:"ConfigurationFiles"`
						Policies []struct {
							PolicyName string `json:"PolicyName"`
							Active     bool   `json:"Active"`
							UserName   string `json:"UserName"`
						} `json:"Policies"`
					}
				}{}
				configFiles := []struct {
					FileName string `json:"FileName"`
					Section  string `json:"Section"`
					Key      string `json:"Key"`
					Value    string `json:"Value"`
				}{}
				policies := []struct {
					PolicyName string `json:"PolicyName"`
					Active     bool   `json:"Active"`
					UserName   string `json:"UserName"`
				}{}
				resources := struct {
					ConfigurationFiles []struct {
						FileName string `json:"FileName"`
						Section  string `json:"Section"`
						Key      string `json:"Key"`
						Value    string `json:"Value"`
					} `json:"ConfigurationFiles"`
					Policies []struct {
						PolicyName string `json:"PolicyName"`
						Active     bool   `json:"Active"`
						UserName   string `json:"UserName"`
					} `json:"Policies"`
				}{}
				preAuditingCSV, err := getCheckByName(fmt.Sprintf("_pre_%s", check.Name))
				if err != nil {
					logger.Log.Error(err.Error())
					break
				}
				if len(check.Results) == 0 && len(preAuditingCSV.Results) == 0 {
					message = "[!] The audit trail target CSV file (CSVTEXTFILE) is not configured.\n"
					check.IssuesPresent = true
				} else {
					message = "[+] Auditing of CSV files is enabled. The following policies have been detected.\n"
					check.IssuesPresent = false
					if len(preAuditingCSV.Results) > 0 {
						for _, r := range preAuditingCSV.Results {
							fileName := r["FILE_NAME"].(string)
							section := r["SECTION"].(string)
							key := r["KEY"].(string)
							value := r["VALUE"].(string)
							configFiles = append(configFiles, struct {
								FileName string "json:\"FileName\""
								Section  string "json:\"Section\""
								Key      string "json:\"Key\""
								Value    string "json:\"Value\""
							}{
								FileName: fileName,
								Section:  section,
								Key:      key,
								Value:    value,
							})
							info += fmt.Sprintf(
								"  - File: %s, Section: %s, Key: %s, Value: %s\n",
								fileName,
								section,
								key,
								value,
							)
						}
					}
					if len(check.Results) > 0 {
						for _, r := range check.Results {
							auditPolicyName := r["AUDIT_POLICY_NAME"].(string)
							isPolicyActiveString := r["IS_AUDIT_POLICY_ACTIVE"].(string)
							userName := r["USER_NAME"].(string)
							isPolicyActive := isPolicyActiveString == "true"
							policies = append(policies, struct {
								PolicyName string "json:\"PolicyName\""
								Active     bool   "json:\"Active\""
								UserName   string "json:\"UserName\""
							}{
								PolicyName: auditPolicyName,
								Active:     isPolicyActive,
								UserName:   userName,
							})
							info += fmt.Sprintf(
								"  - Audit policy name: %s (active: %t), User name: %s\n",
								auditPolicyName,
								isPolicyActive,
								userName,
							)
						}
					}
					resources.ConfigurationFiles = configFiles
					resources.Policies = policies
				}
				affectedResources = append(affectedResources, struct {
					Resources struct {
						ConfigurationFiles []struct {
							FileName string `json:"FileName"`
							Section  string `json:"Section"`
							Key      string `json:"Key"`
							Value    string `json:"Value"`
						} `json:"ConfigurationFiles"`
						Policies []struct {
							PolicyName string `json:"PolicyName"`
							Active     bool   `json:"Active"`
							UserName   string `json:"UserName"`
						} `json:"Policies"`
					}
				}{
					Resources: resources,
				})
				// Convert affectedResources to []interface{}
				var resourcesAsInterface []interface{}
				for _, res := range affectedResources {
					resourcesAsInterface = append(resourcesAsInterface, res)
				}
				caveat += "CAVEAT!! To ensure you thoroughly checked the configuration perform the following manual controls.\n"
				caveat += "  - The default audit trail target is syslog (SYSLOGPROTOCOL) for the system database. If you are using syslog, ensure that it is installed and configured according to your requirements (for example, for writing the audit trail to a remote server). [https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/5c34ecd355e44aa9af3b3e6de4bbf5c1.html#audit-trail-target%%3A-syslog]"
				check.Out = message
				check.Caveat = caveat
				check.AffectedResources = resourcesAsInterface
			case "InternalHostnameResolutionSingle": // output: DONE
				if len(check.Results) == 0 {
					check.IssuesPresent = true
					message = "[!] In file global.ini there is no listeninterface key in [communication] section.\nNo default value is known, this could lead to unexpected behavior. It is suggested to double check the global.ini configuration file and set listeninterface key to the appropriate value.\n"
				} else if len(check.Results) == 1 {
					v := check.Results[0]["VALUE"].(string)
					if v == ".local" {
						check.IssuesPresent = false
						message = fmt.Sprintf("In global.ini files, the [communication] listeninterface is set to %s.\n", v)
					} else {
						check.IssuesPresent = true
						message = fmt.Sprintf("In global.ini files, the [communication] listeninterface is set to %s.\n", v)
						if v == ".global" {
							caveat = "If the listeninterface parameter is set to .global, we strongly recommend that you secure the SAP HANA servers with additional measures such as a firewall and/or TLS/SSL. Otherwise, the internal service ports of the system are exposed and can be used to attack SAP HANA.\n"
						}
					}
				}
				info = "Further information about possible values at: https://help.sap.com/docs/SAP_HANA_PLATFORM/6b94445c94ae495c83a19646e7c3fd56/3fd4912896284029931997903c75d956.html\n"
				check.Out = message
				check.Info = info
				check.Caveat = caveat
			case "InternalHostnameResolutionMultiple": // output: DONE
				internal, err := getCheckByName("InternalHostnameResolutionSingle")
				if err != nil {
					logger.Log.Error(err.Error())
					break
				}
				if len(internal.Results) == 1 {
					v := internal.Results[0]["VALUE"].(string)
					if v == ".internal" {
						if len(check.Results) > 0 {
							caveat = "[-] System has multi-host configuration.\n"
							for _, r := range check.Results {
								key := r["KEY"].(string)
								value := r["VALUE"].(string)
								check.AffectedResources = append(check.AffectedResources, struct {
									Key   string `json:"Key"`
									Value string `json:"Value"`
								}{
									Key:   key,
									Value: value,
								})
								fmt.Printf("  - %s -> %s\n", key, value)
							}
						} else {
							check.IssuesPresent = false
							message = fmt.Sprintf("Even if the system is configured as multi host (listeninterface in [communication] section is %s) no hostname was found in [internal_hostname_resolution] section\n", v)
						}
					} else {
						check.IssuesPresent = false
						utils.Info("The system is not in multi host configuration, listeninterface value in [communication] section is %s\n", v)
					}
					check.Out = message
					check.Info = info
					check.Caveat = caveat
				}
			case "HostnameResolutionReplication": // output: todo
				pre0, err := getCheckByName("_pre_0_HostnameResolutionReplication")
				if err != nil {
					logger.Log.Error(err.Error())
					break
				}
				pre1, err := getCheckByName("_pre_1_HostnameResolutionReplication")
				if err != nil {
					logger.Log.Error(err.Error())
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
			case "InstanceSSFSMasterKey": // output: todo
				if len(check.Results) == 0 {
					utils.Error("[!] Instance SSFS Master Key has never been rotated.\n")
				} else {
					utils.Ok("[+] Instance SSFS Master Key was last rotation time: %s\n", check.Results[0]["VALUE"])
				}
			case "SystemPKISSFSMasterKey": // output: todo
				if len(check.Results) == 0 {
					utils.Error("[!] System PKI SSFS Master Key has never been rotated.\n")
				} else {
					utils.Ok("[+] System PKI SSFS Master Key was last rotation time: %s\n", check.Results[0]["VALUE"])
				}
			case "PasswordHashMethods": // output: todo
				if len(check.Results) == 0 ||
					(len(check.Results) == 1 &&
						strings.Contains(strings.ToUpper(fmt.Sprintf("%s", check.Results[0]["VALUE"])), "sha256")) {
					utils.Warning("[!] Legacy and deprecated password storage method in use (SHA256).\n")
				} else if len(check.Results) == 1 && strings.ToUpper(fmt.Sprintf("%s", check.Results[0]["VALUE"])) == "pbkdf2" {
					utils.Warning("[+] All database user passwords are stored using PBKDF2 (Password-Based Key Derivation Function 2)\n")
				}
			case "RootEncryptionKeys": // output: todo
				for _, record := range check.Results {
					keyVersions := record["VERSIONS"].(int64)
					keyType := record["ROOT_KEY_TYPE"].(string)
					keyCreationDateString := record["CREATION_DATE"].(string)
					keyLastVersionDateString := record["LAST_VERSION_DATE"].(string)
					layout := "2006-01-02 15:04:05"
					keyCreationDate, err := time.Parse(layout, keyCreationDateString)
					if err != nil {
						logger.Log.Error(err.Error())
					}
					keyLastVersionDate, _ := time.Parse(layout, keyLastVersionDateString)
					if err != nil {
						logger.Log.Error(err.Error())
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
			case "DataAndLogVolumeEncryption": // output: todo
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
			case "TraceFiles": // output: todo
				pre0, err := getCheckByName("_pre_0_TraceFiles")
				if err != nil {
					logger.Log.Error(err.Error())
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
			case "DumpFiles": // output: todo
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
			case "SAMLBasedAuthN": // output: todo
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
			case "ConfigurationBlacklist": // output: todo
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
			case "RestrictedFeatures": // output: todo
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
			// Print output
			if check.IssuesPresent {
				utils.Error(message)
				if info != "" {
					utils.Info(info)
				}
			} else {
				utils.Ok(message)
				if info != "" {
					utils.Info(info)
				}
			}
			if check.Caveat != "" {
				utils.Warning(check.Caveat)
			}
			fmt.Println("\n-----------")
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
