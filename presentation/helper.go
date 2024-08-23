package presentation

import (
	"encoding/json"
	"fmt"
	"hana/checks"
	"sort"
	"strings"
)

// hasPrefix checks if a string starts with a given prefix.
//
// Parameters:
// - s: The string to be checked.
// - prefix: The prefix to check for at the start of the string.
//
// Returns:
// - bool: true if the string starts with the given prefix, false otherwise.
func hasPrefix(s, prefix string) bool {
	return strings.HasPrefix(s, prefix)
}

// groupByCategory groups checks by their category and returns a map of category names to checks.
//
// Parameters:
// - checks: A slice of checks.CheckOutput structs representing the checks to be grouped.
// - checkType: The type of checks to group by category.
//
// Returns:
//   - map[string][]checks.CheckOutput: A map where the keys are category names, and the values are slices of checks.CheckOutput structs
//     corresponding to that category.
func groupByCategory(checksList []checks.CheckOutput, checkType string) map[string][]checks.CheckOutput {
	grouped := make(map[string][]checks.CheckOutput)
	for _, check := range checksList {
		if check.CheckType == checkType {
			grouped[check.CheckCategory] = append(grouped[check.CheckCategory], check)
		}
	}
	return grouped
}

// extractCategories extracts unique categories from the checks.
//
// Parameters:
// - checks: A slice of CheckOutput structs from which to extract unique categories.
//
// Returns:
// - []string: A slice of unique category names, sorted alphabetically.
func extractCategories(checkSlice []checks.CheckOutput, checkType string) []string {
	categoryMap := make(map[string]struct{})
	for _, check := range checkSlice {
		if check.CheckType == checkType {
			categoryMap[check.CheckCategory] = struct{}{}
		}
	}

	categories := make([]string, 0, len(categoryMap))
	for category := range categoryMap {
		categories = append(categories, category)
	}

	sort.Strings(categories) // Sort categories alphabetically (optional)
	return categories
}

func scanDetailsOfType(scanDetailsSlice []checks.ScanDetails, checkType string) (checks.ScanDetails, error) {
	for _, scanDetails := range scanDetailsSlice {
		if scanDetails.ScanType == checkType {
			return scanDetails, nil
		}
	}
	return checks.ScanDetails{}, fmt.Errorf("scanDetails of type '%s' not found in the provided scanDetails slice: %v", checkType, scanDetailsSlice)
}

func prettifyJSON(v interface{}) (string, error) {
	jsonData, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}
