package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validChangelog = `# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- New feature in progress

## [1.0.0] - 2024-01-15

### Added
- Initial release
- Core functionality

### Fixed
- Bug fixes

## [0.1.0] - 2024-01-01

### Added
- Beta release

[Unreleased]: https://github.com/example/repo/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/example/repo/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/example/repo/releases/tag/v0.1.0
`

func TestParse(t *testing.T) {
	changelog, err := Parse([]byte(validChangelog))
	require.NoError(t, err)
	require.Len(t, changelog.Entries, 3)

	// Check first entry (Unreleased)
	assert.Equal(t, "Unreleased", changelog.Entries[0].Version)
	assert.Empty(t, changelog.Entries[0].Date)

	// Check second entry (1.0.0)
	assert.Equal(t, "1.0.0", changelog.Entries[1].Version)
	assert.Equal(t, "2024-01-15", changelog.Entries[1].Date)

	// Check links
	assert.Len(t, changelog.Links, 3)
	assert.Equal(t, "https://github.com/example/repo/compare/v0.1.0...v1.0.0", changelog.Links["1.0.0"])
}

func TestFindVersion(t *testing.T) {
	changelog, _ := Parse([]byte(validChangelog))

	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{"exact version", "1.0.0", "1.0.0"},
		{"with v prefix", "v1.0.0", "1.0.0"},
		{"older version", "0.1.0", "0.1.0"},
		{"unreleased", "Unreleased", "Unreleased"},
		{"non-existent", "2.0.0", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := changelog.FindVersion(tt.version)
			if tt.expected == "" {
				assert.Nil(t, entry)
			} else {
				require.NotNil(t, entry)
				assert.Equal(t, tt.expected, entry.Version)
			}
		})
	}
}

func TestValidate_Valid(t *testing.T) {
	result := Validate([]byte(validChangelog))
	assert.True(t, result.IsValid(), "Expected valid changelog, got errors: %v", result.Errors)
}

func TestValidate_MissingTitle(t *testing.T) {
	changelog := `## [Unreleased]

## [1.0.0] - 2024-01-15

### Added
- Something

[Unreleased]: https://example.com
[1.0.0]: https://example.com
`
	result := Validate([]byte(changelog))
	assert.False(t, result.IsValid())
	assert.True(t, hasError(result, "Missing changelog title (# Changelog)"))
}

func TestValidate_MissingUnreleased(t *testing.T) {
	changelog := `# Changelog

## [1.0.0] - 2024-01-15

### Added
- Something

[1.0.0]: https://example.com
`
	result := Validate([]byte(changelog))
	assert.False(t, result.IsValid())
	assert.True(t, hasError(result, "Missing [Unreleased] section"))
}

func TestValidate_InvalidDate(t *testing.T) {
	changelog := `# Changelog

## [Unreleased]

## [1.0.0] - 15-01-2024

### Added
- Something

[Unreleased]: https://example.com
[1.0.0]: https://example.com
`
	result := Validate([]byte(changelog))
	assert.False(t, result.IsValid())
	assert.True(t, hasErrorContaining(result, "ISO 8601"))
}

func TestValidate_InvalidChangeType(t *testing.T) {
	changelog := `# Changelog

## [Unreleased]

### New
- Something

[Unreleased]: https://example.com
`
	result := Validate([]byte(changelog))
	assert.False(t, result.IsValid())
	assert.True(t, hasErrorContaining(result, "Invalid change type"))
}

func TestValidate_MissingLinkDefinition(t *testing.T) {
	changelog := `# Changelog

## [Unreleased]

## [1.0.0] - 2024-01-15

### Added
- Something
`
	result := Validate([]byte(changelog))
	assert.False(t, result.IsValid())
	assert.True(t, hasErrorContaining(result, "Missing link definition for [Unreleased]"))
	assert.True(t, hasErrorContaining(result, "Missing link definition for version [1.0.0]"))
}

func hasError(result *ValidationResult, message string) bool {
	for _, e := range result.Errors {
		if e.Message == message {
			return true
		}
	}
	return false
}

func hasErrorContaining(result *ValidationResult, substr string) bool {
	for _, e := range result.Errors {
		if strings.Contains(e.Message, substr) {
			return true
		}
	}
	return false
}
