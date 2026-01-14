package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

var linkDefPattern = regexp.MustCompile(`(?m)^\[[^\]]+\]:\s+\S+\s*$`)

func stripLinkDefinitions(content string) string {
	// Remove link definition lines from content
	lines := strings.Split(content, "\n")
	var result []string
	for _, line := range lines {
		if !linkDefPattern.MatchString(line) {
			result = append(result, line)
		}
	}
	return strings.TrimSpace(strings.Join(result, "\n"))
}

var extractCmd = &cobra.Command{
	Use:   "extract",
	Short: "Extract a version's changelog entry",
	Long:  `Extract the changelog content for a specific version from a Keep a Changelog file.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		file, _ := cmd.Flags().GetString("file")
		version, _ := cmd.Flags().GetString("version")

		content, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("reading file: %w", err)
		}

		changelog, err := Parse(content)
		if err != nil {
			return fmt.Errorf("parsing changelog: %w", err)
		}

		entry := changelog.FindVersion(version)
		if entry == nil {
			return fmt.Errorf("version %s not found in changelog", version)
		}

		// Output the version header
		if entry.Date != "" {
			fmt.Printf("## [%s] - %s\n\n", entry.Version, entry.Date)
		} else {
			fmt.Printf("## [%s]\n\n", entry.Version)
		}

		// Output content, stripping any link definitions that may have been included
		output := stripLinkDefinitions(entry.Content)
		fmt.Print(output)

		// Append the version's link definition if it exists
		if url, ok := changelog.Links[entry.Version]; ok {
			fmt.Printf("\n\n[%s]: %s\n", entry.Version, url)
		}

		return nil
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all versions in the changelog",
	Long:  `List all version entries found in a Keep a Changelog file.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		file, _ := cmd.Flags().GetString("file")

		content, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("reading file: %w", err)
		}

		changelog, err := Parse(content)
		if err != nil {
			return fmt.Errorf("parsing changelog: %w", err)
		}

		for _, entry := range changelog.Entries {
			if entry.Date != "" {
				fmt.Printf("%s (%s)\n", entry.Version, entry.Date)
			} else {
				fmt.Println(entry.Version)
			}
		}

		return nil
	},
}

func init() {
	extractCmd.Flags().StringP("file", "f", "CHANGELOG.md", "Path to the changelog file")
	extractCmd.Flags().StringP("version", "v", "", "Version to extract (with or without 'v' prefix)")
	_ = extractCmd.MarkFlagRequired("version")

	listCmd.Flags().StringP("file", "f", "CHANGELOG.md", "Path to the changelog file")

	rootCmd.AddCommand(extractCmd)
	rootCmd.AddCommand(listCmd)
}
