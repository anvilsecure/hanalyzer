#!/usr/bin/env python3
"""
SAP HANA Database CheckList Tester

This implements automatic checks for the recommendations as provided by SAP for
Database Users, Roles and Privileges as detailed in the following web page.

https://help.sap.com/viewer/742945a940f240f4a2a0e39f93d3e2d4/2.0.05/en-US/45955420940c4e80a1379bc7270cead6.html

It only requires `hdbcli` to be installed which can simply be installed with
`python3 -m pip install hdbcli`. This is the default Python HANA SQL driver.

Written by Vincent Berg <c_vberg@costco.com / gvb@anvilventures.com> 
on 2020-12-02 during a pentest on Costco's implementation of SAP LaMa.

Fulltime Costco contacts for this would be ntill@, dsilvan@
"""

import os
import argparse
import getpass
import sys
from hdbcli import dbapi


PREDEFINED_USERS = ["SYSTEM", "SYS", "_SYS_AFL", "_SYS_EPM", "_SYS_REPO",
"_SYS_SQL_ANALYZER", "_SYS_STATISTICS", "_SYS_TASK", "_SYS_WORKLOAD_REPLAY",
"_SYS_XB", "_SYS_PLAN_STABILITY", "_SYS_DATA_ANONYMIZATION",
"_SYS_TABLE_REPLICAS", "SYS_TABLE_REPLICA_DATA"]

def check_system_user(cursor):
	print("[+] Checking SYSTEM user")
	sql = '''SELECT USER_DEACTIVATED, DEACTIVATION_TIME,
		LAST_SUCCESSFUL_CONNECT, IS_PASSWORD_LIFETIME_CHECK_ENABLED
		FROM "PUBLIC".USERS WHERE USER_NAME = 'SYSTEM' '''
	cursor.execute(sql)
	rows = cursor.fetchall()
	assert(len(rows) == 1)
	row = rows[0]
	user_deactivated = True if row[0] == "TRUE" else False
	deact_time, last_connect, lifetime_check = row[1:]
	if not user_deactivated:
		print(" ! SYSTEM user is NOT deactivated")
	else:
		print(" - SYSTEM user is deactivated")

def check_password_lifetime(cursor):
	print("[+] Checking Password lifetime")
	sql = '''SELECT	USER_NAME, USER_DEACTIVATED, DEACTIVATION_TIME,
			LAST_SUCCESSFUL_CONNECT FROM "PUBLIC".USERS
		WHERE IS_PASSWORD_LIFETIME_CHECK_ENABLED = 'FALSE' '''
	cursor.execute(sql)
	rows = cursor.fetchmany()
	users = []
	while rows:
		for row in rows:
			user_name, user_deactivated, deact_time, last_connect = row
			if user_name in PREDEFINED_USERS and user_name.startswith("_SYS_"):
				continue
			elif user_name.startswith("XSSQLCC_AUTO_USER_"):
				continue
			users.append(user_name)
		rows = cursor.fetchmany()
	users.sort()
	if len(users) > 0:
		print(" ! Password Lifetime is disabled for: {}".format(", ".join(users)))
	else:
		print(" - Password Lifetime enabled for all users")

def _test_combinations(cursor, priv1, priv2):
	sql = '''SELECT GRANTEE, GRANTEE_TYPE FROM
		EFFECTIVE_PRIVILEGE_GRANTEES
		WHERE OBJECT_TYPE = 'SYSTEMPRIVILEGE'
		AND PRIVILEGE = ? AND GRANTEE NOT IN ('SYSTEM', '_SYS_REPO')
		'''
	cursor.execute(sql, priv1)
	rows = cursor.fetchmany()
	found = {}
	while rows:
		for row in rows:
			found["{}-{}".format(row[0], row[1])] = True
		rows = cursor.fetchmany()
	cursor.execute(sql, priv2)
	rows = cursor.fetchmany()
	count = 0	
	while rows:
		for row in rows:
			key = "{}-{}".format(row[0], row[1])
			if key in found:
				count += 1
				print(" ! {} {} has both {} and {}".format(row[1], row[0], priv1, priv2))
		rows = cursor.fetchmany()
	if count == 0:
		print(" - No critical combintations of {} and {} found".format(priv1, priv2))

def check_critical_combinations_system_privileges(cursor):
	print("[+] Examining critical combinations of system privileges")
	_test_combinations(cursor, "USER ADMIN", "ROLE ADMIN")
	_test_combinations(cursor, "CREATE SCENARIO", "SCENARIO ADMIN")
	_test_combinations(cursor, "AUDIT ADMIN", "AUDIT OPERATOR")
	_test_combinations(cursor, "CREATE STRUCTURED PRIVILEGE", "STRUCTUREDPRIVILEGE ADMIN")

def check_data_admin_system_privilege(cursor):
	print("[+] Examing DATA ADMIN system privilege")
	sql = '''SELECT GRANTEE, GRANTEE_TYPE FROM EFFECTIVE_PRIVILEGE_GRANTEES WHERE OBJECT_TYPE = 'SYSTEMPRIVILEGE' AND
		 PRIVILEGE = 'DATA ADMIN' AND GRANTEE NOT IN ('SYSTEM', '_SYS_REPO') '''
	cursor.execute(sql)
	rows = cursor.fetchall()
	if len(rows) == 0:
		print(" - No user or role was granted the DATA ADMIN system privilege")
		return
	for grantee, grantee_type in rows:
		print(" ! {} {} was granted the DATA ADMIN system privilege".format(grantee_type, grantee))

def check_development_system_privilege(cursor):
	print("[+] Examining development system privileges")
	sql = '''SELECT GRANTEE, GRANTEE_TYPE FROM EFFECTIVE_PRIVILEGE_GRANTEES WHERE OBJECT_TYPE = 'SYSTEMPRIVILEGE' AND
		 PRIVILEGE = 'DEVELOPMENT' AND GRANTEE NOT IN ('SYSTEM', '_SYS_REPO') '''
	cursor.execute(sql)
	rows = cursor.fetchall()
	if len(rows) == 0:
		print(" - No user or role was granted the DEVELOPMENT system privilege")
	for grantee, grantee_type in rows:
		print(" ! {} {} was granted the DEVELOPMENT system privilege".format(grantee_type, grantee))

def check_analytic_privilege(cursor):
	print("[+] Examing analytic privilege _SYS_BI_CP_ALL")
	# _SYS_BI_CP_ALL
	sql = '''SELECT GRANTEE, GRANTEE_TYPE FROM EFFECTIVE_PRIVILEGE_GRANTEES WHERE OBJECT_TYPE = 'ANALYTICALPRIVILEGE' AND OBJECT_NAME = '_SYS_BI_CP_ALL' AND PRIVILEGE = 'EXECUTE' AND GRANTEE NOT IN ('SYSTEM','MODELING', 'CONTENT_ADMIN')'''
	cursor.execute(sql)
	rows = cursor.fetchall()
	if len(rows) == 0:
		print(" - _SYS_BI_CP_ALL is not assigned to any user or role")
		return
	for grantee, grantee_type in rows:
		print(" ! {} {} was granted the analytic privilege _SYS_BI_CP_ALL".format(grantee_type, grantee))

def check_debug_privileges(cursor):
	print("[+] Examining debug privileges")
	sql = '''SELECT GRANTEE, GRANTEE_TYPE FROM GRANTED_PRIVILEGES WHERE PRIVILEGE='DEBUG' OR PRIVILEGE='ATTACH DEBUGGER' '''
	cursor.execute(sql)
	rows = cursor.fetchall()
	if len(rows) == 0:
		print(" - No debug privileges assigned to anyone")
	for grantee, grantee_type in rows:
		print(" ! {} {} was granted debug privileges (DEBUG or ATTACH DEBUGGER)".format(grantee_type, grantee))

def check_predefined_catalog_roles(cursor):
	print("[+] Examining predefined catalog roles")
	sql = '''SELECT GRANTEE, GRANTEE_TYPE FROM GRANTED_ROLES WHERE ROLE_NAME = ? AND GRANTEE NOT IN ('SYSTEM')'''
	cursor.execute(sql, "MODELING")
	rows = cursor.fetchall()
	if len(rows) > 0:
		for grantee, grantee_type in rows:
			print(" ! {} {} was granted the role MODELING".format(grantee_type, grantee))
	else:
		print(" - No user or role was granted the MODELING role")
	cursor.execute(sql, "CONTENT_ADMIN")
	rows = cursor.fetchall()
	if len(rows) > 0:
		for grantee, grantee_type in rows:
			print(" ! {} {} was granted the role CONTENT_ADMIN".format(grantee_type, grantee))
	else:
		print(" - No user or role was granted the CONTENT_ADMIN role")
	sql = '''SELECT GRANTEE, GRANTEE_TYPE FROM EFFECTIVE_ROLE_GRANTEES WHERE ROLE_NAME = 'SAP_INTERNAL_HANA_SUPPORT' ''';
	cursor.execute(sql)
	rows = cursor.fetchall()
	if len(rows) > 0:
		for grantee, grantee_type in rows:
			print(" ! {} {} was granted the role SAP_INTERNAL_HANA_SUPPORT".format(grantee_type, grantee))
	else:
		print(" - No user or role was granted the SAP_INTERNAL_HANA_SUPPORT role")


def check_client_user_parameter(cursor):
	print("[+] Checking for user parameter CLIENT settings")
	sql = '''SELECT VALUE FROM "M_INIFILE_CONTENTS" WHERE KEY='secure_client_parameter' AND SECTION='authorization' '''
	cursor.execute(sql)
	rows = cursor.fetchall()
	if len(rows) == 0:
		print("! secure_client_parameter in [authorization] in global.ini not set")
	else:
		val = rows[0][0]
		if val == "true":
			print(" - secure_cliente_parameter in [authorization] in global.ini set to true")
		else:
			print(" ! secure_client_parameter in [authorization] in global.ini set to false")

	sql = '''SELECT GRANTEE, GRANTEE_TYPE FROM EFFECTIVE_PRIVILEGE_GRANTEES WHERE OBJECT_TYPE = 'SYSTEMPRIVILEGE' AND PRIVILEGE = 'CLIENT PARAMETER ADMIN' '''
	cursor.execute(sql)
	rows = cursor.fetchall()
	if len(rows) > 0:
		for grantee, grantee_type in rows:
			print(" ! {} {} can change the CLIENT user parameter".format(grantee_type, grantee))
	else:
		print(" - No users or roles can change the CLIENT user parameter")

def check_os_file_permissions(cursor):
    print("[+] Check OS File System Permissions")
    sql = '''SELECT VALUE FROM "PUBLIC"."M_INIFILE_CONTENTS" WHERE SECTION = 'import_export' AND KEY = 'file_security' '''
    cursor.execute(sql)
    rows = cursor.fetchall()
    if len(rows) == 0:
        print(" ! file_security in import_export section of indexserver.ini not set")
    else:
        val = rows[0][0]
        if val == "medium":
            print(" + file_security set to default medium value for import/export in indexserver.ini")
        else:
            print(" ! file_security set to {} for import/export indexserver.ini".format(val))
    sql = '''SELECT GRANTEE, GRANTEE_TYPE FROM EFFECTIVE_PRIVILEGE_GRANTEES WHERE OBJECT_TYPE = 'SYSTEMPRIVILEGE' AND (PRIVILEGE = 'EXPORT' OR PRIVILEGE='IMPORT')'''
    cursor.execute(sql)
    rows = cursor.fetchall()
    if len(rows) > 0:
        for grantee, grantee_type in rows:
            print(" ! {} {} can IMPORT/EXPORT".format(grantee_type, grantee))

def check_audit_configuration(cursor):
    print("[+] Checking auditing configuration")
    sql = '''SELECT VALUE FROM "PUBLIC"."M_INIFILE_CONTENTS" WHERE SECTION = 'auditing configuration' AND KEY = 'global_auditing_state' '''
    cursor.execute(sql)
    rows = cursor.fetchall()
    if len(rows) != 0:
        val = rows[0][0]
        if val == "true":
            print(" + Auditing seems to be required")
        else:
            print(" ! Auditing does not seem to be required")

    sql = '''SELECT COUNT(*) FROM "PUBLIC"."AUDIT_POLICIES" '''
    cursor.execute(sql)
    row = cursor.fetchone()
    val = row[0]
    if val == 0:
        print(" ! No audit policies configured whatsoever")
    else:
        print(" - {} Audit policies configured".format(val))

    sql = '''SELECT COUNT(*) FROM "PUBLIC"."M_INIFILE_CONTENTS" WHERE SECTION = 'auditing configuration' AND VALUE = 'CSVTEXTFILE' '''
    cursor.execute(sql)
    row = cursor.fetchone()
    cnt1 = row[0] if row else 0
    sql = '''SELECT * FROM "PUBLIC"."AUDIT_POLICIES" WHERE TRAIL_TYPE='csv' '''
    cursor.execute(sql)
    row = cursor.fetchone()
    cnt2 = row[0] if row else 0

    if cnt1 != 0 or cnt2 != 0:
        print(" ! There are CSV text files configured as audit trails. These have severe restrictions and should not be used in production!")
    else:
        print(" - No CSV text files configured as audit trails")

def run():
    parser = argparse.ArgumentParser(description="HANA Security Checklist Tool")
    parser.add_argument("--username", metavar='USERNAME', help="username to authenticate with", default="U99021028", required=True)
    parser.add_argument("--host", metavar='HOST', help="hostname to connect to", required=True)
    parser.add_argument("--port", metavar='PORT', help="HANA DB TCP port to use (default: 30015)", default=30015, type=int)
    args = parser.parse_args()

    ssh_pass = os.environ.get("SSH_PASS")
    if not ssh_pass:
        args.password = getpass.getpass()
    else:
        args.password = ssh_pass

    try:
        conn = dbapi.connect(address=args.host, port=args.port, user=args.username, password=args.password)
        cursor = conn.cursor()
    except dbapi.Error as e:
        print(e.errortext)
        sys.exit(1)
    except Exception as e:
        print(e)
        sys.exit(1)

    check_system_user(cursor)
    check_password_lifetime(cursor)
    check_critical_combinations_system_privileges(cursor)
    check_data_admin_system_privilege(cursor)
    check_development_system_privilege(cursor)
    check_analytic_privilege(cursor)
    check_debug_privileges(cursor)
    check_predefined_catalog_roles(cursor)
    check_client_user_parameter(cursor)
    check_os_file_permissions(cursor)
    check_audit_configuration(cursor)

    cursor.close()
    conn.close()

    sys.exit(0)

if __name__ == "__main__":
	run()
