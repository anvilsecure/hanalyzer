package checks

import (
	"hana/db"
	"log"
)

func newCheck(name, description, link, recommendation, query string, parameters []string) *Check {
	if name == "" || query == "" {
		log.Fatalf("Query creation failed. Name and Query fields required.")
	}
	return &Check{
		Name:           name,
		Description:    description,
		Link:           link,
		Recommendation: recommendation,
		Query:          query,
		Parameters:     parameters,
		Results:        db.Results{},
		Result:         false,
	}
}

func isPredefined(user string) bool {
	for _, u := range PREDEFINED_USERS {
		if user == u {
			return true
		}
	}
	return false
}

func getAllUsers() {
	results := db.Query(`Select USER_NAME from "SYS"."USERS";`)
	for _, r := range results {
		userName := string(r["USER_NAME"].([]uint8))
		userNames = append(userNames, userName)
	}
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func subslice(s1 []string, s2 []string) bool {
	if len(s1) > len(s2) {
		return false
	}
	for _, e := range s1 {
		if !contains(s2, e) {
			return false
		}
	}
	return true
}

func remove(slice []string, s int) []string {
	return append(slice[:s], slice[s+1:]...)
}

// difference returns the elements in `a` that aren't in `b`.
func difference(a, b []string) []string {
	mb := make(map[string]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []string
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}
