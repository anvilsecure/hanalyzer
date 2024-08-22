package presentation

import (
	"sort"
	"strings"
)

// Function to check if a string starts with a given prefix
func hasPrefix(s, prefix string) bool {
	return strings.HasPrefix(s, prefix)
}

// groupByCategory groups checks by their category and returns a map of category names to checks
func groupByCategory(checks []CheckOutput, checkType string) map[string][]CheckOutput {
	grouped := make(map[string][]CheckOutput)
	for _, check := range checks {
		if check.CheckType == checkType {
			grouped[check.CheckCategory] = append(grouped[check.CheckCategory], check)
		}
	}
	return grouped
}

// extractCategories extracts unique categories from the checks
func extractCategories(checks []CheckOutput) []string {
	categoryMap := make(map[string]struct{})
	for _, check := range checks {
		categoryMap[check.CheckCategory] = struct{}{}
	}

	categories := make([]string, 0, len(categoryMap))
	for category := range categoryMap {
		categories = append(categories, category)
	}

	sort.Strings(categories) // Sort categories alphabetically (optional)
	return categories
}
