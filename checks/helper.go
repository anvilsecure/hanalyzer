package checks

import (
	"errors"
	"fmt"
	"hana/db"
	"hana/ssh"
	"log"
	"log/slog"
	"reflect"
	"strings"
	"time"
)

func executeQuery(query string) (Results, error) {
	var results Results
	res, err := db.Query(query)
	if err != nil {
		return nil, err
	}
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
				val = fmt.Sprint(x.Format(readableTimeFormat))
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
	return results, nil
}

func prepareAndExecute(check *Check) error {
	if len(check.Parameters) > 1 {
		return fmt.Errorf("we are currently not supporting multiple parameters")
	}
	var res Results
	var err error
	for _, p := range check.Parameters {
		stmt := fmt.Sprintf(check.Control, p)
		res, err = executeQuery(stmt)
		if err != nil {
			return err
		}
	}
	check.Results = res
	return nil
}

func ExecuteChecks(checkType CheckType) {
	for _, check := range CheckList {
		if check.Type == checkType {
			switch check.Type {
			case QueryType:
				if len(check.Parameters) == 0 {
					if check.Name == "CriticalCombinations" {
						/*
							This is a workaround. It is not possible to issue queries like this
							`SELECT DISTINCT USER_NAME, PRIVILEGE FROM "PUBLIC".EFFECTIVE_PRIVILEGES WHERE OBJECT_TYPE = SYSTEMPRIVILEGE' AND USER_NAME IN (SELECT USER_NAME FROM "SYS".USERS);`
							This is a known limitation in SAP HANA when querying M_* or EFFECTIVE_* views.
							https://community.sap.com/t5/technology-q-a/system-table-to-get-all-users-and-roles-assigned-to-that-users/qaq-p/12183502
						*/
						err := getAllUsers()
						if err != nil {
							check.Error = err
							break
						}
						p := "USER_NAME = '" + strings.Join(userNames, "' OR USER_NAME = '") + "'"
						check.Control = fmt.Sprintf(criticalCombinations, p)
					}
					check.Results, check.Error = executeQuery(check.Control)
				} else {
					if err := prepareAndExecute(check); err != nil {
						check.Error = err
						break
					}
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

func newCheck(checkType CheckType, name, category, description, link, recommendation, control string, parameters []string) *Check {
	if name == "" || control == "" {
		log.Fatalf("Query creation failed. Name and Control fields required.")
	}
	return &Check{
		Type:           checkType,
		Name:           name,
		Category:       category,
		Description:    description,
		Link:           Link{Title: strings.Join([]string{category, name}, " - "), URL: link},
		Recommendation: recommendation,
		Control:        control,
		Parameters:     parameters,
		Results:        Results{},
		IssuesPresent:  false,
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

func getAllUsers() error {
	results, err := db.Query(`Select USER_NAME from "SYS"."USERS";`)
	if err != nil {
		return err
	}
	for _, r := range results {
		userName := string(r["USER_NAME"].([]uint8))
		userNames = append(userNames, userName)
	}
	return nil
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

func (check *Check) listGrantees() (map[string]entity, error) {
	grantees := make(map[string]entity)
	if check.checkEmptyResult() {
		return nil, fmt.Errorf("empty result set for grantee list")
	}
	for _, r := range check.Results {
		user := r["GRANTEE"].(string)
		granteeType := r["GRANTEE_TYPE"].(string)
		privilege := r["PRIVILEGE"].(string)
		grantees[user] = entity{
			Name:       user,
			Type:       granteeType,
			Privileges: append(grantees[user].Privileges, privilege),
		}
	}
	return grantees, nil
}

func printGrantees(grantees map[string]entity) string {
	out := ""
	for k, grantee := range grantees {
		out += fmt.Sprintf("  - %s (entity type: %s)\n", k, grantee.Type)
	}
	return out
}

func getCheckByName(name string) (*Check, error) {
	for _, c := range CheckList {
		if c.Name == name {
			return c, nil
		}
	}
	return nil, fmt.Errorf("no check found with name %s", name)
}

// checkEmptyResult function checks if the result set of the executed Check is empty or not
func (check *Check) checkEmptyResult() bool {
	if len(check.Results) == 0 {
		slog.Warn("check returned empty result set", "name", check.Name)
		return true
	}
	return false
}

// GenericSliceToInterfaceSlice converts a slice of any type to a slice of interface{}
// Parameters:
//
//	original - the original slice (of any given type)
//
// Returns:
//
//	[]interface{} - a generic slice of interface objects
func GenericSliceToInterfaceSlice[T any](original []T) (interfaceSlice []interface{}) {
	if original == nil {
		return nil
	}
	for _, element := range original {
		interfaceSlice = append(interfaceSlice, element)
	}
	return interfaceSlice
}

// Equal compares the Check instance pointed to by c1 with the CheckOutput instance
// pointed to by c2 to determine if they are equal based on their Name field.
//
// Parameters:
//
//	c2 - A pointer to another CheckOutput instance to compare with the Check instance
//	     pointed to by c1.
//
// Returns:
//
//	bool - A boolean value indicating whether the Name fields of both Check and CheckOutput
//	       instances are equal (true) or not (false).
//
// Note:
//
//	This method only compares the Name fields of the Check and CheckOutput instances. If
//	you need to compare other fields, you will need to extend this method
//	accordingly.
func (c1 *Check) Equal(c2 *CheckOutput) (equal bool) {
	equal = false
	if c1.Name == c2.CheckName {
		equal = true
	}
	return
}

// In function controls if the Check instance pointed to by c1 is present in the provided
// slice of CheckOutput instances. The comparison is done using the Equal method,
// which compares Check and CheckOutput instances based on their Name field.
//
// Parameters:
//
//	checks - A slice of CheckOutput instances to search within.
//
// Returns:
//
//	bool - A boolean value indicating whether the Check instance pointed to
//	       by c1 is found in the provided CheckOutput slice (true) or not (false).
func (c1 *Check) In(checks []CheckOutput) bool {
	for _, check := range checks {
		if c1.Equal(&check) {
			return true
		}
	}
	return false
}
