<img alt="gitleaks badge" src="https://img.shields.io/badge/protected%20by-gitleaks-blue">

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

# Roadmap

## SAP HANA Database Checklists and Recommendations

### Recommendations for Database Users, Roles, and Privileges
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

### Recommendations for File System and Operating System
- [x] Operating System Users (add as caveat manual check)
- [x] OS File System Permissions (porting from @gvb)
- [x] OS Security Patches (add as caveat manual check)
- [x] OS sudo Configuration (add as caveat manual check)

### Recommendations for Auditing Configuration
- [ ] Auditing (porting from @gvb)
- [ ] Audit Trail Target: syslog
- [ ] Audit Trail Target: CSV Text File

### Recommendations for Network Configuration
- [ ] Open Ports
- [ ] Internal Host Name Resolution in Single-Host System
- [ ] Internal Host Name Resolution in Multiple-Host System
- [ ] Host Name Resolution in System Replication

### Recommendations for Data Encryption
- [ ] Instance SSFS Master Key
- [ ] System PKI SSFS Master Key
- [ ] Root Encryption Keys
- [ ] Encryption Key of the SAP HANA Secure User Store (hdbuserstore)
- [ ] Data and Log Volume Encryption

### Recommendations for Trace and Dump Files
- [ ] Trace Files
- [ ] Dump Files

### Recommendations for Tenant Database Management
- [ ] SAML-Based User Authentication
- [ ] Configuration Blacklist
- [ ] Restricted Features