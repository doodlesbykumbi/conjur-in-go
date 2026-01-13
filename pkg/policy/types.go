package policy

import (
	"gopkg.in/yaml.v3"
)

type Resource interface {
	unused() // to prevent Resource from being used as a type
}

type Resources interface {
	Policy | Variable | User | Group | Layer | Grant | Host | Delete | Permit | Deny | HostFactory | Webservice
}

type Group struct {
	Resource    `yaml:"-"`
	Id          string                 `yaml:"id,omitempty"`
	Annotations map[string]interface{} `yaml:"annotations,omitempty"`
	Owner       ResourceRef            `yaml:"owner,omitempty"`
}

// UnmarshalYAML for Group handles both scalar (just ID) and mapping forms
func (g *Group) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		g.Id = value.Value
		return nil
	}
	type groupAlias Group
	return value.Decode((*groupAlias)(g))
}

type Annotations map[string]interface{}

type Variable struct {
	Resource    `yaml:"-"`
	Id          string                 `yaml:"id"`
	Annotations map[string]interface{} `yaml:"annotations,omitempty"`
	Kind        string                 `yaml:"kind,omitempty"`
}

// UnmarshalYAML for Variable handles both scalar (just ID) and mapping forms
func (v *Variable) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		v.Id = value.Value
		return nil
	}
	type variableAlias Variable
	return value.Decode((*variableAlias)(v))
}

type User struct {
	Resource    `yaml:"-"`
	Id          string                 `yaml:"id"`
	Owner       ResourceRef            `yaml:"owner,omitempty"`
	Annotations map[string]interface{} `yaml:"annotations,omitempty"`
}

// UnmarshalYAML for User handles both scalar (just ID) and mapping forms
func (u *User) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		u.Id = value.Value
		return nil
	}
	type userAlias User
	return value.Decode((*userAlias)(u))
}

type Policy struct {
	Resource    `yaml:"-"`
	Id          string                 `yaml:"id"`
	Annotations map[string]interface{} `yaml:"annotations,omitempty"`
	Owner       ResourceRef            `yaml:"owner,omitempty"`
	Body        PolicyStatements       `yaml:"body,omitempty"`
}

type Layer struct {
	Resource    `yaml:"-"`
	Id          string                 `yaml:"id,omitempty"`
	Annotations map[string]interface{} `yaml:"annotations,omitempty"`
	Owner       ResourceRef            `yaml:"owner,omitempty"`
}

type Grant struct {
	Resource `yaml:"-"`
	Role     ResourceRef   `yaml:"role"`
	Member   ResourceRef   `yaml:"-"` // Use custom unmarshaler
	Members  []ResourceRef `yaml:"-"` // Plural form
}

type Host struct {
	Resource    `yaml:"-"`
	Id          string                 `yaml:"id,omitempty"`
	Owner       ResourceRef            `yaml:"owner,omitempty"`
	Body        PolicyStatements       `yaml:"body,omitempty"`
	Annotations map[string]interface{} `yaml:"annotations,omitempty"`
}

type Delete struct {
	Resource `yaml:"-"`
	Record   ResourceRef `yaml:"record"`
}

type Permit struct {
	Resource   `yaml:"-"`
	Role       ResourceRef   `yaml:"role"`
	Privileges []Privilege   `yaml:"privileges,flow"`
	Resources  []ResourceRef `yaml:"-"` // Supports both singular and plural form
}

type Deny struct {
	Resource   `yaml:"-"`
	Role       ResourceRef   `yaml:"role"`
	Privileges []Privilege   `yaml:"privileges,flow"`
	Resources  []ResourceRef `yaml:"-"` // Supports both singular and plural form
}

type HostFactory struct {
	Resource    `yaml:"-"`
	Id          string                 `yaml:"id"`
	Annotations map[string]interface{} `yaml:"annotations,omitempty"`
	Owner       ResourceRef            `yaml:"owner,omitempty"`
	Layers      []ResourceRef          `yaml:"layers,omitempty"`
}

type Webservice struct {
	Resource    `yaml:"-"`
	Id          string                 `yaml:"id"`
	Annotations map[string]interface{} `yaml:"annotations,omitempty"`
	Owner       ResourceRef            `yaml:"owner,omitempty"`
}

// UnmarshalYAML for Grant handles both "member" and "members" fields
func (g *Grant) UnmarshalYAML(value *yaml.Node) error {
	// Temporary struct to capture raw YAML
	type grantRaw struct {
		Role    ResourceRef   `yaml:"role"`
		Member  ResourceRef   `yaml:"member"`
		Members []ResourceRef `yaml:"members"`
	}
	var raw grantRaw
	if err := value.Decode(&raw); err != nil {
		return err
	}
	g.Role = raw.Role
	// If members (plural) is provided, use it; otherwise use member (singular)
	if len(raw.Members) > 0 {
		g.Members = raw.Members
	} else if raw.Member.Id != "" {
		g.Members = []ResourceRef{raw.Member}
	}
	// Also set Member for backward compatibility
	if len(g.Members) > 0 {
		g.Member = g.Members[0]
	}
	return nil
}

// UnmarshalYAML for Permit handles both "resource" and "resources" fields
func (p *Permit) UnmarshalYAML(value *yaml.Node) error {
	// Temporary struct to capture raw YAML
	type permitRaw struct {
		Role       ResourceRef   `yaml:"role"`
		Privileges []Privilege   `yaml:"privileges"`
		Resource   ResourceRef   `yaml:"resource"`
		Resources  []ResourceRef `yaml:"resources"`
	}
	var raw permitRaw
	if err := value.Decode(&raw); err != nil {
		return err
	}
	p.Role = raw.Role
	p.Privileges = raw.Privileges
	// If resources (plural) is provided, use it; otherwise use resource (singular)
	if len(raw.Resources) > 0 {
		p.Resources = raw.Resources
	} else if raw.Resource.Id != "" {
		p.Resources = []ResourceRef{raw.Resource}
	}
	return nil
}

// UnmarshalYAML for Deny handles both "resource" and "resources" fields
func (d *Deny) UnmarshalYAML(value *yaml.Node) error {
	// Temporary struct to capture raw YAML
	type denyRaw struct {
		Role       ResourceRef   `yaml:"role"`
		Privileges []Privilege   `yaml:"privileges"`
		Resource   ResourceRef   `yaml:"resource"`
		Resources  []ResourceRef `yaml:"resources"`
	}
	var raw denyRaw
	if err := value.Decode(&raw); err != nil {
		return err
	}
	d.Role = raw.Role
	d.Privileges = raw.Privileges
	// If resources (plural) is provided, use it; otherwise use resource (singular)
	if len(raw.Resources) > 0 {
		d.Resources = raw.Resources
	} else if raw.Resource.Id != "" {
		d.Resources = []ResourceRef{raw.Resource}
	}
	return nil
}

type PolicyStatements []Resource

func (s *PolicyStatements) UnmarshalYAML(value *yaml.Node) error {
	var statements []Resource
	for _, node := range value.Content {
		var statement Resource

		switch node.Tag {
		case KindPolicy.Tag():
			var policy Policy
			if err := node.Decode(&policy); err != nil {
				return err
			}
			statement = policy
		case KindGroup.Tag():
			var group Group
			if err := node.Decode(&group); err != nil {
				// In order to allow empty (inherited) IDs for groups we ignore this error
				// and allow an empty group statement to be used
				statement = Group{}
				break
			}
			statement = group
		case KindUser.Tag():
			var user User
			if err := node.Decode(&user); err != nil {
				return err
			}
			statement = user
		case KindVariable.Tag():
			var variable Variable
			if err := node.Decode(&variable); err != nil {
				return err
			}
			statement = variable
		case KindLayer.Tag():
			var layer Layer
			if len(node.Value) > 0 || len(node.Content) > 0 {
				if err := node.Decode(&layer); err != nil {
					return err
				}
			}
			statement = layer
		case KindGrant.Tag():
			var grant Grant
			if err := node.Decode(&grant); err != nil {
				return err
			}
			statement = grant
		case KindHost.Tag():
			var host Host
			if len(node.Value) > 0 || len(node.Content) > 0 {
				if err := node.Decode(&host); err != nil {
					return err
				}
			}
			statement = host
		case KindDelete.Tag():
			var delete Delete
			if err := node.Decode(&delete); err != nil {
				return err
			}
			statement = delete
		case KindPermit.Tag():
			var permit Permit
			if err := node.Decode(&permit); err != nil {
				return err
			}
			statement = permit
		case KindDeny.Tag():
			var deny Deny
			if err := node.Decode(&deny); err != nil {
				return err
			}
			statement = deny
		case KindHostFactory.Tag():
			var hf HostFactory
			if err := node.Decode(&hf); err != nil {
				return err
			}
			statement = hf
		case KindWebservice.Tag():
			var ws Webservice
			if err := node.Decode(&ws); err != nil {
				return err
			}
			statement = ws
		}
		statements = append(statements, statement)
	}

	*s = statements

	return nil
}

func (p Policy) MarshalYAML() (interface{}, error) {
	return MarshalYAMLWithTag(p, KindPolicy)
}

func (v Variable) MarshalYAML() (interface{}, error) {
	return MarshalYAMLWithTag(v, KindVariable)
}

func (u User) MarshalYAML() (interface{}, error) {
	return MarshalYAMLWithTag(u, KindUser)
}

func (g Group) MarshalYAML() (interface{}, error) {
	return MarshalYAMLWithTag(g, KindGroup)
}

func (l Layer) MarshalYAML() (interface{}, error) {
	return MarshalYAMLWithTag(l, KindLayer)
}

func (g Grant) MarshalYAML() (interface{}, error) {
	// Create a struct with the singular "member" field for YAML output
	type grantOut struct {
		Role   ResourceRef `yaml:"role"`
		Member ResourceRef `yaml:"member,omitempty"`
	}
	out := grantOut{
		Role: g.Role,
	}
	if len(g.Members) > 0 {
		out.Member = g.Members[0]
	} else {
		out.Member = g.Member
	}
	node := &yaml.Node{}
	node.Kind = yaml.MappingNode
	if err := node.Encode(&out); err != nil {
		return nil, err
	}
	node.Tag = KindGrant.Tag()
	node.Style = yaml.TaggedStyle
	return node, nil
}

func (h Host) MarshalYAML() (interface{}, error) {
	return MarshalYAMLWithTag(h, KindHost)
}

func (d Delete) MarshalYAML() (interface{}, error) {
	return MarshalYAMLWithTag(d, KindDelete)
}

func (p Permit) MarshalYAML() (interface{}, error) {
	// Create a struct with the singular "resource" field for YAML output
	type permitOut struct {
		Role       ResourceRef `yaml:"role"`
		Privileges []Privilege `yaml:"privileges,flow"`
		Resource   ResourceRef `yaml:"resource,omitempty"`
	}
	out := permitOut{
		Role:       p.Role,
		Privileges: p.Privileges,
	}
	if len(p.Resources) > 0 {
		out.Resource = p.Resources[0]
	}
	node := &yaml.Node{}
	node.Kind = yaml.MappingNode
	if err := node.Encode(&out); err != nil {
		return nil, err
	}
	node.Tag = KindPermit.Tag()
	node.Style = yaml.TaggedStyle
	return node, nil
}

func (d Deny) MarshalYAML() (interface{}, error) {
	// Create a struct with the singular "resource" field for YAML output
	type denyOut struct {
		Role       ResourceRef `yaml:"role"`
		Privileges []Privilege `yaml:"privileges,flow"`
		Resource   ResourceRef `yaml:"resource,omitempty"`
	}
	out := denyOut{
		Role:       d.Role,
		Privileges: d.Privileges,
	}
	if len(d.Resources) > 0 {
		out.Resource = d.Resources[0]
	}
	node := &yaml.Node{}
	node.Kind = yaml.MappingNode
	if err := node.Encode(&out); err != nil {
		return nil, err
	}
	node.Tag = KindDeny.Tag()
	node.Style = yaml.TaggedStyle
	return node, nil
}

func (hf HostFactory) MarshalYAML() (interface{}, error) {
	return MarshalYAMLWithTag(hf, KindHostFactory)
}

func (ws Webservice) MarshalYAML() (interface{}, error) {
	return MarshalYAMLWithTag(ws, KindWebservice)
}
