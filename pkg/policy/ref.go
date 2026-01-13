package policy

import "gopkg.in/yaml.v3"

type ResourceRef struct {
	Id   string `yaml:"id"`
	Kind Kind
}

func UserRef(id string) ResourceRef {
	return ResourceRef{
		Id:   id,
		Kind: KindUser,
	}
}

func GroupRef(id string) ResourceRef {
	return ResourceRef{
		Id:   id,
		Kind: KindGroup,
	}
}

func LayerRef(id string) ResourceRef {
	return ResourceRef{
		Id:   id,
		Kind: KindLayer,
	}
}

func HostRef(id string) ResourceRef {
	return ResourceRef{
		Id:   id,
		Kind: KindHost,
	}
}

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
