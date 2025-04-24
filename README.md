<img alt="gitleaks badge" src="https://img.shields.io/badge/protected%20by-gitleaks-blue">

# Goal
This tool was designed to analyze configuration of SAP HANA instances and compare it with official security guidelines.

> In the following demo the .env file contains the following line  
> `export HANA_DB_PASSWORD=_myVerySecr3tPassw0rd_`

![Demo](./demo.gif)

Once you ran the tool, you can open the output file with a browser, and you'll get the following HTML report.

<div align="center">
    <img alt="Initial screen" src="https://github.com/anvilventures/hana/blob/main/pictures/00.png" width="412px"/> 
    <img alt="Example of issue" src="https://github.com/anvilventures/hana/blob/main/pictures/01.png" width="412px"/>
</div>


# How to use it

## Modes

There are two possible mode of analysis
* querying the DB (36 checks)
* invoking commands via SSH on the DB server (1 check)

> If possible we try to perform checks by querying the DB, to avoid requiring SSH access.
The only check that was not possible to implement via query is [Encryption Key of the SAP HANA Secure User Store](https://help.sap.com/docs/SAP_HANA_COCKPIT/afa922439b204e9caf22c78b6b69e4f2/904911eb0fe54124b10dfaeadb5337ce.html?version=2.12.0.0#encryption-key-of-the-sap-hana-secure-user-store-(hdbuserstore)).

```bash
$ hanalyzer -h
Tool to analyze SAP Hana database configuration against official SAP guidelines.

Usage:
  hanalyzer [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  query       Perform checks by querying the DB.
  ssh         Use ssh to perform the following checks on the DB server:
                        - Encryption Key of the SAP HANA Secure User Store

Flags:
  -h, --help   help for hanalyzer

Use "hanalyzer [command] --help" for more information about a command.
```

### Query mode
Most of the checks are performed via DB queries.

> The DB password must be exported to environment variable HANA_DB_PASSWORD to avoid passing it via CLI arguments

```bash
$ hanalyzer -h
Perform checks by querying the DB.

Usage:
  hanalyzer query [flags]

Flags:
      --conf string          Provide configuration file (required if --host, --db-port, --db-username, --db-password, and --sid are not provided by CLI)
      --db-port int          Database port (default 39015)
      --db-username string   Database username
  -h, --help                 help for query
      --host string          Database host
      --json-output string   JSON output file
      --sid string           Instance SID

```

You can use a configuration file (`--conf <file.yml>`) or provide the required parameters via flag ([Query mode examples](#query-mode-examples)).


### SSH mode
One check is performed by issuing a command via SSH.

> The SSH password must be exported to environment variable HANA_SSH_PASSWORD to avoid passing it via CLI arguments

```bash
$ hanalyzer -h
Use SSH to perform the following checks on the DB server:
                        - Encryption Key of the SAP HANA Secure User Store

Usage:
  hanalyzer ssh [flags]

Flags:
      --conf string           Provide configuration file (required if --host, --ssh-port, --ssh-username, and --ssh-password are not provided by CLI)
  -h, --help                  help for ssh
      --host string           Database host
      --json-output string    JSON output file
      --ssh-port int          SSH username (default 22)
      --ssh-username string   SSH username
```

You can use a configuration file (`--conf <file.yml>`) or provide the required parameters via flag ([SSH mode examples](#ssh-mode-examples)).

### Examples
#### Query mode examples
Using a [configuration file](#configuration-file)
```bash
$ hanalyzer query --conf .\conf.yml
Check: CheckSystemUser
[!] User SYSTEM is ACTIVE (USER_DEACTIVATED=FALSE).
Last successful connection was in date 2024-07-19 15:19:46.
-----------
Check: CheckPasswordLifetime
[!] The following users have password lifetime disabled(IS_PASSWORD_LIFETIME_CHECK_ENABLED=FALSE).
  - SYS
  - SYSTEM
  - SAPDBCTRL
  - TEL_ADMIN
-----------
Check: SystemPrivileges
[!] Please review the following entities (users/roles) because they might have too high privileges:
[I] Breakdown per grantee
......
```

Using CLI parameters
```bash
$ hanalyzer query --host <hostname/IP_address> --sid <SID> --db-username <DBUsername> --db-password <DBPassword>
Check: CheckSystemUser
[!] User SYSTEM is ACTIVE (USER_DEACTIVATED=FALSE).
Last successful connection was in date 2024-07-19 15:19:46.
-----------
Check: CheckPasswordLifetime
[!] The following users have password lifetime disabled(IS_PASSWORD_LIFETIME_CHECK_ENABLED=FALSE).
  - SYS
  - SYSTEM
  - SAPDBCTRL
  - TEL_ADMIN
-----------
Check: SystemPrivileges
[!] Please review the following entities (users/roles) because they might have too high privileges:
[I] Breakdown per grantee
......
```

#### SSH mode examples
Using a [configuration file](#configuration-file)
```bash
$ hanalyzer ssh --conf .\conf.yml
Check: CheckSystemUser
Check: EncryptionKeySAPHANASecureUserStore
[+] Encryption key (SSFS_HDB.KEY) found, Secure User Store is correctly encrypted.
-----------
```

Using CLI parameters
```bash
$ hanalyzer ssh --host <hostname/IP_address> --ssh-username <DBUsername> --ssh-password <DBPassword>
Check: EncryptionKeySAPHANASecureUserStore
[+] Encryption key (SSFS_HDB.KEY) found, Secure User Store is correctly encrypted.
```

# Configuration file

In the project root create the following `conf.yml` file

```yml
host: HOST_NAME
sid: DB_SID
database:
  port: PORT
  username: USERNAME (e.g., system)
  password: PASSWORD
ssh:
  port: PORT
  username: USERNAME (e.g., hxeadm)
  password: PASSWORD

```

# Cross Compile
To cross compile the executables for every architecture and every OS it was used a Makefile with no external dependency to increase the reusability.

## Example
### MacOS arm64
`make darwin/arm64`
### Linux amd64
`make linux/amd64`
### Windows amd64
`make windows/amd64`

## Makefile
Building the realease for the detected architecture and OS
```bash
$ make
/Library/Developer/CommandLineTools/usr/bin/make build/darwin/arm64
Building for darwin/arm64...
GOOS=darwin, GOARCH=arm64, OUTPUT_NAME=hanalyzer_darwin_arm64
```

# Roadmap

## SAP HANA Database Checklists and Recommendations

### [Recommendations for Database Users, Roles, and Privileges](https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/45955420940c4e80a1379bc7270cead6.html?version=2.0.05&locale=en-US#password-lifetime-of-database-users)
- [x] SYSTEM User (porting from @gvb)
- [x] Password Lifetime of Database Users (porting from @gvb)
- [x] System Privileges
- [x] System Privileges: Critical Combinations (porting from @gvb)
- [x] System Privilege: DATA ADMIN (porting from @gvb)
- [x] System Privilege: DEVELOPMENT (porting from @gvb)
- [x] Analytic Privilege: _SYS_BI_CP_ALL (porting from @gvb)
- [x] Debug Privileges (porting from @gvb)
- [x] Predefined Catalog Role CONTENT_ADMIN (porting from @gvb)
- [x] Predefined Catalog Role MODELING
- [x] Predefined Catalog Role SAP_INTERNAL_HANA_SUPPORT
- [x] Predefined Repository Roles
- [x] User Parameter CLIENT (porting from @gvb)
- [x] Related Information

### [Recommendations for File System and Operating System](https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/1bea52d12332472cb4a7658300241ce8.html)
- [x] Operating System Users (add as caveat manual check)
- [x] OS File System Permissions (porting from @gvb)
- [x] OS Security Patches (add as caveat manual check)
- [x] OS sudo Configuration (add as caveat manual check)

### [Recommendations for Auditing Configuration](https://help.sap.com/docs/SAP_HANA_PLATFORM/742945a940f240f4a2a0e39f93d3e2d4/5c34ecd355e44aa9af3b3e6de4bbf5c1.html)
- [x] Auditing (porting from @gvb)
- [x] Audit Trail Target: syslog (add as caveat manual check)
- [x] Audit Trail Target: CSV Text File

### [Recommendations for Network Configuration](https://help.sap.com/docs/SAP_HANA_COCKPIT/afa922439b204e9caf22c78b6b69e4f2/eccef06eabe545e68d5019bcb6d8e342.html?locale=en-US&version=2.12.0.0)
- [x] Open Ports (add as caveat manual check)
- [x] Internal Host Name Resolution in Single-Host System
- [x] Internal Host Name Resolution in Multiple-Host System
- [x] Host Name Resolution in System Replication

### [Recommendations for Data Encryption](https://help.sap.com/docs/SAP_HANA_COCKPIT/afa922439b204e9caf22c78b6b69e4f2/904911eb0fe54124b10dfaeadb5337ce.html?locale=en-US&version=2.12.0.0)
- [x] Instance SSFS Master Key
- [x] System PKI SSFS Master Key
- [x] Root Encryption Keys
- [x] Encryption Key of the SAP HANA Secure User Store (hdbuserstore)
- [x] Data and Log Volume Encryption

### [Recommendations for Trace and Dump Files](https://help.sap.com/docs/SAP_HANA_COCKPIT/afa922439b204e9caf22c78b6b69e4f2/9630172f36564ee5ba26c13c054a35e1.html?locale=en-US&version=2.12.0.0)
- [x] Trace Files
- [x] Dump Files

### [Recommendations for Tenant Database Management](https://help.sap.com/docs/SAP_HANA_COCKPIT/afa922439b204e9caf22c78b6b69e4f2/a6e033bd909948d5b12caeb2ceba20d4.html?locale=en-US&version=2.12.0.0)
- [x] SAML-Based User Authentication
- [x] Configuration Blacklist
- [x] Restricted Features

# Notes

* http://hxehost:8090
* https://hxehost:39030

ssh hxeadm@hxehost

IF using a VM, after the setup process you will encounter the following error

```
Free and used memory in the system
==================================
Before collection
-------------------------------------------------------------------------
             total       used       free     shared    buffers     cached
Mem:           11G        10G       1.5G        68M       2.0M       2.4G
-/+ buffers/cache:       7.8G       3.9G
Swap:         4.0G         0B       4.0G
After  collection
-------------------------------------------------------------------------
             total       used       free     shared    buffers     cached
Mem:           11G        10G       1.6G        68M       2.0M       2.6G
-/+ buffers/cache:       7.5G       4.3G
Swap:         4.0G         0B       4.0G

Please wait while XSA starts.  This may take a while...OK
Change XSA_ADMIN user password on SystemDB database...
Change XSA_DEV user password on SystemDB database...
* 10: authentication failed SQLSTATE: 28000
Password already changed.  However, the new password you specified is invalid.
```

This is solved [here](https://community.sap.com/t5/technology-q-a/hana-express-edition-28000-password-already-changed/qaq-p/12321995#answer-13321675)

```
HDB start
XSA reset-certificate
 
hdbsql -u system -n hxehost:39013
alter user XSA_ADMIN activate user now;
alter user XSA_ADMIN password "<PASSWORD>";
alter user XSA_DEV activate user now; 
alter user XSA_DEV password "<PASSWORD>"; 
```

> Caveat!!
> For the setup script to work you need the same password for
> * Master password 
> * SYSTEM 
> * XSA_ADMIN
> * XSA_DEV

Before setup startup the host and let it start all the processes, otherwise it could be possible that the setup script will not be able to connect to every process.

**!! VMs expose port 39015**