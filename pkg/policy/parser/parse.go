package parser

import (
	"io"

	"gopkg.in/yaml.v3"
)

// Parse parses policy YAML from a reader and returns the parsed statements.
func Parse(r io.Reader) (Statements, error) {
	var statements Statements
	decoder := yaml.NewDecoder(r)
	if err := decoder.Decode(&statements); err != nil {
		return nil, err
	}
	return statements, nil
}
