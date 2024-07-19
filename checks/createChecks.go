package checks

import (
	"fmt"
	"strings"
)

func CreateChecks(checkType CheckType) {
	if checkType == QueryType {
		//////////////////////////////////////////////////////////////////////////////
		name := "CheckSystemUser"
		description := "The database user SYSTEM is the most powerful database user with irrevocable system privileges. The SYSTEM user is active after database creation."
		link := "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/45955420940c4e80a1379bc7270cead6.html?version=2.0.05&locale=en-US#system-user"
		recommendation := "Use SYSTEM to create database users with the minimum privilege set required for their duties (for example, user administration, system administration). Then deactivate SYSTEM."
		CheckList = append(CheckList, newCheck(
			QueryType,
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
			QueryType,
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
			QueryType,
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
		CheckList = append(CheckList, newCheck(
			QueryType,
			name,
			description,
			link,
			recommendation,
			"placeholder",
			[]string{},
		))
		//////////////////////////////////////////////////////////////////////////////
		name = "SystemPrivilegeDataAdmin"
		description = "The system privilege DATA ADMIN is a powerful privilege. It authorizes a user to execute all data definition language (DDL) commands in the SAP HANA database. Only the users SYSTEM and _SYS_REPO have this privilege by default."
		link = "https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/45955420940c4e80a1379bc7270cead6.html?locale=en-US#system-privilege%3A-data-admin"
		recommendation = "No user or role in a production database should have this privilege."
		CheckList = append(CheckList, newCheck(
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
			name,
			description,
			link,
			recommendation,
			dataAndLogVolumeEncryption,
			[]string{},
		))
		//////////////////////////////////////////////////////////////////////////////
		name = "_pre_0_TraceFiles"
		description = "preliminary query #1 for trace files check"
		link = "https://help.sap.com/docs/SAP_HANA_COCKPIT/afa922439b204e9caf22c78b6b69e4f2/9630172f36564ee5ba26c13c054a35e1.html?locale=en-US&version=2.12.0.0#trace-files"
		recommendation = "- Enable tracing to troubleshoot specific problems only and then disable.\n- Exercise caution when setting or changing the trace level. A high trace level may expose certain security-relevant data (for example, database trace level DEBUG or SQL trace level ALL_WITH_RESULTS).\n- Delete trace files that are no longer needed."
		CheckList = append(CheckList, newCheck(
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
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
			QueryType,
			name,
			description,
			link,
			recommendation,
			restrictedFeatures,
			[]string{},
		))
	} else if checkType == SSHType {
		name := "EncryptionKeySAPHANASecureUserStore"
		description := "The secure user store (hdbuserstore) is a tool installed with the SAP HANA client. It is used to store SAP HANA connection information, including user passwords, securely on clients. Information contained in the SAP HANA secure user store is encrypted using a unique encryption key."
		link := "https://help.sap.com/docs/SAP_HANA_COCKPIT/afa922439b204e9caf22c78b6b69e4f2/904911eb0fe54124b10dfaeadb5337ce.html?locale=en-US&version=2.12.0.0#encryption-key-of-the-sap-hana-secure-user-store-(hdbuserstore)"
		recommendation := "If you are using the current version of the SAP HANA client, there is no need to change the encryption key of the secure user store. However, if you are using an older version of the SAP HANA client, we recommend changing the encryption key after installation of the SAP HANA client."
		CheckList = append(CheckList, newCheck(
			SSHType,
			name,
			description,
			link,
			recommendation,
			encryptionKeySAPHANASecureUserStore,
			[]string{},
		))
		//////////////////////////////////////////////////////////////////////////////
	}
}
