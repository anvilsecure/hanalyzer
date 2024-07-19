package checks

import (
	"errors"
	"fmt"
	"hana/db"
	"hana/ssh"
	"hana/utils"
	"log"
	"os"
	"reflect"
	"strings"
	"time"
)

func executeQuery(query string) (results Results) {
	res := db.Query(query)
	// Do something with the map
	for _, r := range res {
		var resMap = make(map[string]interface{})
		for key, val := range r {
			switch t := val.(type) {
			case []uint8:
				val = string(val.([]uint8))
			case bool:
				val = val.(bool)
			case int64:
				val = val.(int64)
			case time.Time:
				_ = t
				x := val.(time.Time)
				val = fmt.Sprint(x.Format("2006-01-02 15:04:05"))
			default:
				if rv := reflect.ValueOf(val); !rv.IsValid() || rv.IsNil() {
					val = "NULL"
				}
			}
			//fmt.Println("Key:", key, "Val:", val, "Value Type:", reflect.TypeOf(val))
			resMap[key] = val
		}
		results = append(results, resMap)
	}
	return
}

func prepareAndExecute(check *Check) {
	if len(check.Parameters) > 1 {
		utils.Error("We aren't ready yet to prepare statements w/ mutiple parameters :[")
		os.Exit(1)
	}
	var res Results
	for _, p := range check.Parameters {
		stmt := fmt.Sprintf(check.Control, p)
		res = executeQuery(stmt)
	}
	check.Results = res
}

func ExecuteChecks(checkType CheckType) {
	for _, check := range CheckList {
		if check.Type == checkType {
			switch check.Type {
			case QueryType:
				if len(check.Parameters) == 0 {
					if check.Name == "CriticalCombinations" {
						getAllUsers()
						p := "USER_NAME = '" + strings.Join(userNames, "' OR USER_NAME = '") + "'"
						check.Control = fmt.Sprintf(criticalCombinations, p)
					}
					check.Results = executeQuery(check.Control)
				} else {
					prepareAndExecute(check)
				}
			case SSHType:
				stdOut, stdErr, err := ssh.ExecCommand(check.Control)
				var sshErr *ssh.SSHError
				if err != nil && !errors.As(err, &sshErr) {
					log.Println(err)
				}
				if err != nil && errors.As(err, &sshErr) {
					check.Results = []map[string]interface{}{
						{"stdOut": stdOut, "stdErr": stdErr, "err": sshErr},
					}
				}
				check.Results = []map[string]interface{}{
					{"stdOut": stdOut, "stdErr": stdErr, "err": fmt.Errorf("")},
				}
			}
		}
	}
}

func newCheck(checkType CheckType, name, description, link, recommendation, control string, parameters []string) *Check {
	if name == "" || control == "" {
		log.Fatalf("Query creation failed. Name and Control fields required.")
	}
	return &Check{
		Type:           checkType,
		Name:           name,
		Description:    description,
		Link:           link,
		Recommendation: recommendation,
		Control:        control,
		Parameters:     parameters,
		Results:        Results{},
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

func (check *Check) listGrantees() map[string]entity {
	grantees := make(map[string]entity)
	for _, r := range check.Results {
		user := r["GRANTEE"].(string)
		grantees[user] = entity{
			Type:       r["GRANTEE_TYPE"].(string),
			Name:       user,
			Privileges: append(grantees[user].Privileges, r["PRIVILEGE"].(string)),
		}
	}
	return grantees
}

func printGrantees(grantees map[string]entity) {
	for k, grantee := range grantees {
		fmt.Printf("  - %s (entity type: %s)\n", k, grantee.Type)
	}
}

func getCheckByName(name string) (*Check, error) {
	for _, c := range CheckList {
		if c.Name == name {
			return c, nil
		}
	}
	return nil, fmt.Errorf("no check found with name %s", name)
}
