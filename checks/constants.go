package checks

import (
	"time"
)

type CheckType string

const (
	QueryType CheckType = "query"
	SSHType   CheckType = "ssh"
)

type Results []map[string]interface{}

type Check struct {
	Type              CheckType
	Name              string
	Description       string
	Link              string
	Recommendation    string
	Control           string
	Results           Results
	Parameters        []string
	IssuesPresent     bool
	Error             error
	Out               string
	AffectedResources []interface{}
	Info              string
}

type entity struct {
	Type       string
	Name       string
	Privileges []string
}

const (
	checkSystemUser                      string = `SELECT USER_NAME, USER_DEACTIVATED, DEACTIVATION_TIME, LAST_SUCCESSFUL_CONNECT FROM "PUBLIC".USERS WHERE USER_NAME = 'SYSTEM'`
	checkPasswordLifetime                string = `SELECT USER_NAME, USER_DEACTIVATED, DEACTIVATION_TIME, LAST_SUCCESSFUL_CONNECT FROM "PUBLIC".USERS WHERE IS_PASSWORD_LIFETIME_CHECK_ENABLED = 'FALSE'`
	systemPrivileges                     string = `SELECT DISTINCT GRANTEE, GRANTEE_TYPE, PRIVILEGE FROM EFFECTIVE_PRIVILEGE_GRANTEES WHERE OBJECT_TYPE = 'SYSTEMPRIVILEGE' AND PRIVILEGE IN (%s) AND GRANTEE NOT IN ('SYSTEM', '_SYS_REPO') AND GRANTEE NOT IN ('SYSTEM', '_SYS_REPO')`
	criticalCombinations                 string = `SELECT DISTINCT USER_NAME, PRIVILEGE FROM "PUBLIC"."EFFECTIVE_PRIVILEGES" WHERE OBJECT_TYPE = 'SYSTEMPRIVILEGE' AND (%s)`
	dataAdmin                            string = `SELECT * FROM EFFECTIVE_PRIVILEGE_GRANTEES WHERE OBJECT_TYPE = 'SYSTEMPRIVILEGE' AND PRIVILEGE = '%s' AND GRANTEE NOT IN ('SYSTEM','_SYS_REPO');`
	analyticPrivilege                    string = `SELECT * FROM EFFECTIVE_PRIVILEGE_GRANTEES WHERE OBJECT_TYPE = 'ANALYTICALPRIVILEGE' AND OBJECT_NAME = '%s' AND PRIVILEGE = 'EXECUTE' AND GRANTEE NOT IN ('SYSTEM','MODELING', 'CONTENT_ADMIN');`
	debugPrivilege                       string = `SELECT * FROM GRANTED_PRIVILEGES WHERE PRIVILEGE='%s' OR PRIVILEGE='ATTACH DEBUGGER';`
	predefinedCatalogRole                string = `SELECT * FROM GRANTED_ROLES WHERE ROLE_NAME = '%s' AND GRANTEE NOT IN ('SYSTEM');`
	predefinedCatalogRoleGeneral         string = `SELECT * FROM EFFECTIVE_ROLE_GRANTEES WHERE ROLE_NAME = '%s';`
	_pre_userParameterClient             string = `SELECT * FROM "M_INIFILE_CONTENTS" WHERE KEY='secure_client_parameter';`
	userParameterClient                  string = `SELECT * FROM EFFECTIVE_PRIVILEGE_GRANTEES WHERE OBJECT_TYPE = 'SYSTEMPRIVILEGE' AND PRIVILEGE = 'CLIENT PARAMETER ADMIN';`
	_pre_osFsPermissions                 string = `SELECT * FROM "PUBLIC"."M_INIFILE_CONTENTS" WHERE SECTION = 'import_export' AND KEY = 'file_security';`
	osFsPermissions                      string = `SELECT * FROM EFFECTIVE_PRIVILEGE_GRANTEES WHERE (OBJECT_TYPE = 'SYSTEMPRIVILEGE') AND (PRIVILEGE = 'EXPORT' OR PRIVILEGE='IMPORT');`
	_pre_auditing                        string = `SELECT VALUE FROM "PUBLIC"."M_INIFILE_CONTENTS" WHERE SECTION = 'auditing configuration' AND KEY = 'global_auditing_state'`
	auditing                             string = `SELECT COUNT(*) as COUNT FROM "PUBLIC"."AUDIT_POLICIES"`
	_pre_auditingCSV                     string = `SELECT * FROM "PUBLIC" . "M_INIFILE_CONTENTS" WHERE SECTION = 'auditing configuration' --AND VALUE = 'CSVTEXTFILE';`
	auditingCSV                          string = `SELECT * FROM "PUBLIC"."AUDIT_POLICIES" WHERE TRAIL_TYPE='CSV';`
	internalHostnameResolutionSingle     string = `SELECT * FROM "PUBLIC"."M_INIFILE_CONTENTS" WHERE SECTION = 'communication' AND KEY = 'listeninterface';`
	internalHostnameResolutionMultiple   string = `SELECT * FROM "PUBLIC"."M_INIFILE_CONTENTS" WHERE SECTION = 'internal_hostname_resolution';`
	_pre_0_hostnameResolutionReplication string = `SELECT * FROM "PUBLIC"."M_INIFILE_CONTENTS" WHERE SECTION = 'system_replication_communication' AND KEY = 'listeninterface';`
	_pre_1_hostnameResolutionReplication string = `SELECT * FROM "PUBLIC"."M_INIFILE_CONTENTS" WHERE SECTION = 'system_replication_communication' AND KEY = 'internal_hostname_resolution';`
	hostnameResolutionReplication        string = `SELECT * FROM "PUBLIC"."M_INIFILE_CONTENTS" WHERE SECTION = 'system_replication_communication' AND KEY = 'allowed_sender';`
	instanceSSFSMasterKey                string = `SELECT * FROM M_HOST_INFORMATION WHERE KEY IN ('SSFS_MASTERKEY_CHANGED','ssfs_masterkey_changed')`
	systemPKISSFSMasterKey               string = `SELECT * FROM M_HOST_INFORMATION WHERE KEY IN ('SSFS_MASTERKEY_SYSTEMPKI_CHANGED','ssfs_masterkey_systempki_changed')`
	passwordHashMethods                  string = `SELECT * FROM "PUBLIC"."M_INIFILE_CONTENTS" WHERE FILE_NAME = 'global.ini' AND SECTION = 'authentication' AND KEY = 'password_hash_methods'`
	rootEncryptionKeys                   string = `SELECT ROOT_KEY_TYPE,COUNT(CREATE_TIMESTAMP) AS Versions,MIN(TO_SECONDDATE(CREATE_TIMESTAMP)) AS CREATION_DATE, MAX(TO_SECONDDATE(CREATE_TIMESTAMP)) AS LAST_VERSION_DATE FROM ENCRYPTION_ROOT_KEYS WHERE ROOT_KEY_STATUS IN ('ACTIVE','DEACTIVATED') GROUP BY ROOT_KEY_TYPE`
	dataAndLogVolumeEncryption           string = `SELECT SCOPE,IS_ENCRYPTION_ACTIVE FROM M_ENCRYPTION_OVERVIEW`
	_pre_0_TraceFiles                    string = `SELECT VIEW_NAME FROM SYS.VIEWS WHERE VIEW_NAME = 'M_TRACEFILES';`
	traceFiles                           string = `SELECT * FROM SYS.M_TRACEFILES`
	dumpFiles                            string = `SELECT * FROM SYS.FULL_SYSTEM_INFO_DUMPS`
	SAMLBasedAuthN                       string = `SELECT * FROM PSES WHERE PURPOSE ='SAML' OR PURPOSE ='SSL'`
	configurationBlacklist               string = `SELECT * FROM "PUBLIC". "M_INIFILE_CONTENTS" WHERE FILE_NAME = 'multidb.ini'`
	restrictedFeatures                   string = `SELECT * FROM "PUBLIC". "M_CUSTOMIZABLE_FUNCTIONALITIES"`
	// SSH commands
	encryptionKeySAPHANASecureUserStore string = `hdbuserstore list`
)

type Duration struct {
	Literal string
	Value   time.Duration
}

const (
	MONTH = time.Duration(731) * time.Hour
)

var (
	CheckList        []*Check
	userNames        []string
	PREDEFINED_USERS = []string{"SYSTEM", "SYS", "_SYS_AFL", "_SYS_EPM", "_SYS_REPO", "_SYS_SQL_ANALYZER", "_SYS_STATISTICS", "_SYS_TASK", "_SYS_WORKLOAD_REPLAY", "_SYS_XB", "_SYS_TABLE_REPLICAS", "SYS_TABLE_REPLICA_DATA"}
	ADMIN_PRIVILEGES = []string{"CATALOG READ", "TRACE ADMIN", "ADAPTER ADMIN", "AGENT ADMIN", "AUDIT ADMIN", "AUDIT OPERATOR", "BACKUP ADMIN", "BACKUP OPERATOR", "CERTIFICATE ADMIN", "CREATE REMOTE SOURCE", "CREDENTIAL ADMIN", "ENCRYPTION ROOT KEY ADMIN", "EXTENDED STORAGE ADMIN", "INIFILE ADMIN", "LDAP ADMIN", "LICENSE ADMIN", "LOG ADMIN", "MONITOR ADMIN", "OPTIMIZER ADMIN", "RESOURCE ADMIN", "SAVEPOINT ADMIN", "SERVICE ADMIN", "SESSION ADMIN", "SSL ADMIN", "TABLE ADMIN", "TRUST ADMIN", "VERSION ADMIN", "WORKLOAD ADMIN", "WORKLOAD ANALYZE ADMIN", "WORKLOAD CAPTURE ADMIN", "WORKLOAD REPLAY ADMIN"}
	DANGEROUS_COMBO  = [][]string{
		{"USER ADMIN", "ROLE ADMIN"},
		// {"USER ADMIN", "INIFILE ADMIN"}, // this is safe, only for testing purposes
		{"CREATE SCENARIO", "SCENARIO ADMIN"},
		{"AUDIT ADMIN", "AUDIT OPERATOR"},
		{"CREATE STRUCTURED PRIVILEGE", "STRUCTUREDPRIVILEGE ADMIN"},
	}
	oneMonth Duration = Duration{
		Literal: "one month",
		Value:   1 * MONTH,
	}
	threeMonths Duration = Duration{
		Literal: "three months",
		Value:   3 * MONTH,
	}
	sixMonths Duration = Duration{
		Literal: "six months",
		Value:   6 * MONTH,
	}
)
