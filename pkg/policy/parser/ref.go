package parser

import "gopkg.in/yaml.v3"

// ResourceRef represents a reference to a resource with its kind and ID.
type ResourceRef struct {
	Id   string `yaml:"id"`
	Kind Kind
}

// UserRef creates a ResourceRef for a user.
func UserRef(id string) ResourceRef {
	return ResourceRef{
		Id:   id,
		Kind: KindUser,
	}
}

// GroupRef creates a ResourceRef for a group.
func GroupRef(id string) ResourceRef {
	return ResourceRef{
		Id:   id,
		Kind: KindGroup,
	}
}

// LayerRef creates a ResourceRef for a layer.
func LayerRef(id string) ResourceRef {
	return ResourceRef{
		Id:   id,
		Kind: KindLayer,
	}
}

// HostRef creates a ResourceRef for a host.
func HostRef(id string) ResourceRef {
	return ResourceRef{
		Id:   id,
		Kind: KindHost,
	}
}

// VariableRef creates a ResourceRef for a variable.
func VariableRef(id string) ResourceRef {
	return ResourceRef{
		Id:   id,
		Kind: KindVariable,
	}
}

func (r *ResourceRef) UnmarshalYAML(value *yaml.Node) (err error) {
	var id string
	if err = value.Decode(&id); err != nil {
		return
	}

	r.Id = id
	r.Kind, err = KindString(value.Tag[1:])
	if err != nil {
		return
	}
	return
}

func (r ResourceRef) MarshalYAML() (interface{}, error) {
	return &yaml.Node{
		Kind:  yaml.ScalarNode,
		Value: r.Id,
		Tag:   r.Kind.Tag(),
		Style: yaml.TaggedStyle,
	}, nil
}
