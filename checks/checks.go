package checks

const (
	CheckSystemUser string = `SELECT USER_DEACTIVATED, DEACTIVATION_TIME, LAST_SUCCESSFUL_CONNECT, 
					IS_PASSWORD_LIFETIME_CHECK_ENABLED FROM "PUBLIC".USERS
					WHERE USER_NAME = 'SYSTEM'`
)

var AllChecks []string

func init() {
	AllChecks = append(
		AllChecks,
		CheckSystemUser,
	)
}
