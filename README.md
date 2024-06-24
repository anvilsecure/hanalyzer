<img alt="gitleaks badge" src="https://img.shields.io/badge/protected%20by-gitleaks-blue">

# Configuration file

In the project root create the following `conf.yml` file

```yml
database:
  host: HOST_NAME
  port: PORT
  username: USERNAME (e.g., system)
  password: PASSWORD
host:
  username: USERNAME (e.g., hxeadm)
  password: PASSWORD
instance:
  sid: DB_SID
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
- [ ] Dump Files

### [Recommendations for Tenant Database Management](https://help.sap.com/docs/SAP_HANA_COCKPIT/afa922439b204e9caf22c78b6b69e4f2/a6e033bd909948d5b12caeb2ceba20d4.html?locale=en-US&version=2.12.0.0)
- [ ] SAML-Based User Authentication
- [ ] Configuration Blacklist
- [ ] Restricted Features

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