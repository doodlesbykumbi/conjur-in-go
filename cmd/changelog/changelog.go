package main

import (
	"bytes"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
)

// ChangelogEntry represents a single version entry in the changelog
type ChangelogEntry struct {
	Version string
	Date    string
	Content string
}

// Changelog represents a parsed Keep a Changelog file
type Changelog struct {
	Entries []ChangelogEntry
	Links   map[string]string
}

// FindVersion finds a version entry by version string
func (c *Changelog) FindVersion(version string) *ChangelogEntry {
	version = strings.TrimPrefix(version, "v")

	for i := range c.Entries {
		entryVersion := strings.TrimPrefix(c.Entries[i].Version, "v")
		if entryVersion == version {
			return &c.Entries[i]
		}
	}
	return nil
}

// Parse parses a Keep a Changelog formatted markdown file
func Parse(source []byte) (*Changelog, error) {
	md := goldmark.New()
	reader := text.NewReader(source)
	ctx := parser.NewContext()
	doc := md.Parser().Parse(reader, parser.WithContext(ctx))

	changelog := &Changelog{
		Links: make(map[string]string),
	}

	// Extract link definitions from parser context
	for _, ref := range ctx.References() {
		changelog.Links[string(ref.Label())] = string(ref.Destination())
	}

	// Collect all h2 headings with their positions from the AST
	type headingInfo struct {
		version      string
		date         string
		contentStart int
		headingStart int
	}
	var headings []headingInfo

	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}

		if heading, ok := n.(*ast.Heading); ok && heading.Level == 2 {
			headingText := extractHeadingText(heading, source)
			version, date := parseVersionHeading(headingText)

			lines := heading.Lines()
			headingStart := 0
			contentStart := 0
			if lines.Len() > 0 {
				headingStart = lines.At(0).Start
				contentStart = lines.At(lines.Len() - 1).Stop
			}

			headings = append(headings, headingInfo{
				version:      version,
				date:         date,
				contentStart: contentStart,
				headingStart: headingStart,
			})
		}

		return ast.WalkContinue, nil
	})

	// Extract content for each entry using AST positions
	for i, h := range headings {
		var contentEnd int
		if i+1 < len(headings) {
			contentEnd = headings[i+1].headingStart
		} else {
			contentEnd = len(source)
		}

		content := ""
		if h.contentStart < contentEnd {
			content = strings.TrimSpace(string(source[h.contentStart:contentEnd]))
		}

		changelog.Entries = append(changelog.Entries, ChangelogEntry{
			Version: h.version,
			Date:    h.date,
			Content: content,
		})
	}

	return changelog, nil
}

func extractHeadingText(node ast.Node, source []byte) string {
	var buf bytes.Buffer
	for child := node.FirstChild(); child != nil; child = child.NextSibling() {
		if textNode, ok := child.(*ast.Text); ok {
			buf.Write(textNode.Segment.Value(source))
		} else if link, ok := child.(*ast.Link); ok {
			for linkChild := link.FirstChild(); linkChild != nil; linkChild = linkChild.NextSibling() {
				if textNode, ok := linkChild.(*ast.Text); ok {
					buf.Write(textNode.Segment.Value(source))
				}
			}
		}
	}
	return buf.String()
}

func parseVersionHeading(heading string) (version, date string) {
	heading = strings.TrimSpace(heading)

	heading = strings.TrimPrefix(heading, "[")
	if idx := strings.Index(heading, "]"); idx != -1 {
		version = heading[:idx]
		rest := strings.TrimSpace(heading[idx+1:])
		if strings.HasPrefix(rest, "- ") {
			date = strings.TrimSpace(rest[2:])
		}
	} else if idx := strings.Index(heading, " - "); idx != -1 {
		version = strings.TrimSpace(heading[:idx])
		date = strings.TrimSpace(heading[idx+3:])
	} else {
		version = heading
	}

	return version, date
}
