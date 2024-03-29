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

## Roadmap
### Porting from @gvb
- [x] SYSTEM User
- [x] Password Lifetime of Database Users
- [x] System Privileges: Critical Combinations
- [x] System Privilege: DATA ADMIN
- [x] System Privilege: DEVELOPMENT
- [x] Analytic Privilege: _SYS_BI_CP_ALL
- [x] Debug privileges
- [x] Predefined Catalog Role CONTENT_ADMIN
- [ ] User Parameter CLIENT
- [ ] OS file permissions
- [ ] Audit configuration

### Other checks
- [x] System Privileges
- [x] Predefined Catalog Role MODELING
- [x] Predefined Catalog Role SAP_INTERNAL_HANA_SUPPORT
- [ ] Predefined Repository Roles