package policy

import (
	"reflect"

	"gopkg.in/yaml.v3"
)

// copyStructWithoutMethods avoids infinite recursion when marshaling
func copyStructWithoutMethods(in interface{}) interface{} {
	t := reflect.TypeOf(in)
	if t.Kind() != reflect.Struct {
		return nil
	}

	// Create a new type that embeds the original struct type
	// but with no methods.
	fields := make([]reflect.StructField, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.Type.Kind() == reflect.Func {
			continue // skip methods
		}
		fields = append(fields, field)
	}
	newType := reflect.StructOf(fields)

	// Create a new value of the new type and set its fields to the
	// values of the original value.
	inValue := reflect.ValueOf(in)
	newValue := reflect.New(newType).Elem()
	for i := 0; i < newType.NumField(); i++ {
		newValue.Field(i).Set(inValue.FieldByName(newType.Field(i).Name))
	}

	return newValue.Interface()
}

func MarshalYAMLWithTag[T Resources](v T, kind Kind) (interface{}, error) {
	data := copyStructWithoutMethods(v)

	node := &yaml.Node{}
	node.Kind = yaml.MappingNode
	if err := node.Encode(&data); err != nil {
		return nil, err
	}

	// Avoid emitting strings like `- !variable {}` and instead emit `- !variable` by setting Kind to ScalarNode
	// when the resource struct is empty!
	if len(node.Content) == 0 {
		node.Kind = yaml.ScalarNode
	}

	node.Tag = kind.Tag()
	node.Style = yaml.TaggedStyle
	return node, nil
}
