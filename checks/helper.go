package checks

func isPredefined(user string) bool {
	for _, u := range PREDEFINED_USERS {
		if user == u {
			return true
		}
	}
	return false
}
