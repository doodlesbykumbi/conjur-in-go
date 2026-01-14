package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

// ValidationError represents a single validation issue
type ValidationError struct {
	Line    int
	Message string
}

// ValidationResult holds all validation errors
type ValidationResult struct {
	Errors []ValidationError
}

func (r *ValidationResult) AddError(line int, message string) {
	r.Errors = append(r.Errors, ValidationError{Line: line, Message: message})
}

func (r *ValidationResult) IsValid() bool {
	return len(r.Errors) == 0
}

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate a changelog follows Keep a Changelog spec",
	Long: `Validate that a changelog file follows the Keep a Changelog specification.

Checks include:
- File has a title (# Changelog)
- Has an [Unreleased] section
- Version entries use correct format: ## [X.Y.Z] - YYYY-MM-DD
- Dates are in ISO 8601 format (YYYY-MM-DD)
- Change types are valid (Added, Changed, Deprecated, Removed, Fixed, Security)
- Link definitions exist for all versions`,
	RunE: func(cmd *cobra.Command, args []string) error {
		file, _ := cmd.Flags().GetString("file")

		content, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("reading file: %w", err)
		}

		result := Validate(content)

		if result.IsValid() {
			fmt.Println("✓ Changelog is valid")
			return nil
		}

		fmt.Printf("Found %d issue(s):\n\n", len(result.Errors))
		for _, e := range result.Errors {
			if e.Line > 0 {
				fmt.Printf("  Line %d: %s\n", e.Line, e.Message)
			} else {
				fmt.Printf("  %s\n", e.Message)
			}
		}

		os.Exit(1)
		return nil
	},
}

var (
	dateRegex    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	versionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	validTypes   = map[string]bool{
		"Added":      true,
		"Changed":    true,
		"Deprecated": true,
		"Removed":    true,
		"Fixed":      true,
		"Security":   true,
	}
)

// Validate checks a changelog against Keep a Changelog spec
func Validate(source []byte) *ValidationResult {
	result := &ValidationResult{}
	lines := strings.Split(string(source), "\n")

	hasTitle := false
	hasUnreleased := false
	versions := make(map[string]bool)

	changelog, _ := Parse(source)

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		// Check for title
		if strings.HasPrefix(trimmed, "# ") {
			hasTitle = true
			if !strings.Contains(strings.ToLower(trimmed), "changelog") {
				result.AddError(lineNum, "Title should contain 'Changelog'")
			}
		}

		// Check version headers
		if strings.HasPrefix(trimmed, "## [") {
			// Extract version
			end := strings.Index(trimmed, "]")
			if end > 4 {
				version := trimmed[4:end]

				if strings.ToLower(version) == "unreleased" {
					hasUnreleased = true
				} else {
					versions[version] = true

					// Check version format
					if !versionRegex.MatchString(version) {
						result.AddError(lineNum, fmt.Sprintf("Version '%s' should follow semantic versioning (X.Y.Z)", version))
					}

					// Check date format
					if strings.Contains(trimmed, " - ") {
						parts := strings.SplitN(trimmed[end+1:], " - ", 2)
						if len(parts) == 2 {
							date := strings.TrimSpace(parts[1])
							if !dateRegex.MatchString(date) {
								result.AddError(lineNum, fmt.Sprintf("Date '%s' should be in ISO 8601 format (YYYY-MM-DD)", date))
							}
						}
					} else {
						result.AddError(lineNum, fmt.Sprintf("Version '%s' is missing a release date", version))
					}
				}
			}
		}

		// Check change type headers
		if strings.HasPrefix(trimmed, "### ") {
			changeType := strings.TrimPrefix(trimmed, "### ")
			if !validTypes[changeType] {
				result.AddError(lineNum, fmt.Sprintf("Invalid change type '%s'. Valid types: Added, Changed, Deprecated, Removed, Fixed, Security", changeType))
			}
		}
	}

	if !hasTitle {
		result.AddError(0, "Missing changelog title (# Changelog)")
	}

	if !hasUnreleased {
		result.AddError(0, "Missing [Unreleased] section")
	}

	// Check link definitions
	if changelog != nil {
		for version := range versions {
			if _, ok := changelog.Links[version]; !ok {
				result.AddError(0, fmt.Sprintf("Missing link definition for version [%s]", version))
			}
		}

		if hasUnreleased {
			if _, ok := changelog.Links["Unreleased"]; !ok {
				result.AddError(0, "Missing link definition for [Unreleased]")
			}
		}
	}

	return result
}

func init() {
	validateCmd.Flags().StringP("file", "f", "CHANGELOG.md", "Path to the changelog file")
	rootCmd.AddCommand(validateCmd)
}
