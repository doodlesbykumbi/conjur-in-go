package parser

import (
	"gopkg.in/yaml.v3"
)

// Statement is a marker interface for policy statements.
type Statement interface {
	isStatement()
}

// resources is a type constraint for all resource types that can be marshaled with tags.
type resources interface {
	Policy | Variable | User | Group | Layer | Grant | Host | Delete | Permit | Deny | HostFactory | Webservice
}

// Group represents a group in a policy.
type Group struct {
	Statement   `yaml:"-"`
	Id          string                 `yaml:"id,omitempty"`
	Annotations map[string]interface{} `yaml:"annotations,omitempty"`
	Owner       ResourceRef            `yaml:"owner,omitempty"`
}

func (Group) isStatement() {}

// UnmarshalYAML for Group handles both scalar (just ID) and mapping forms
func (g *Group) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		g.Id = value.Value
		return nil
	}
	type groupAlias Group
	return value.Decode((*groupAlias)(g))
}

// Variable represents a variable in a policy.
type Variable struct {
	Statement   `yaml:"-"`
	Id          string                 `yaml:"id"`
	Owner       ResourceRef            `yaml:"owner,omitempty"`
	Annotations map[string]interface{} `yaml:"annotations,omitempty"`
	Kind        string                 `yaml:"kind,omitempty"`
}

func (Variable) isStatement() {}

// UnmarshalYAML for Variable handles both scalar (just ID) and mapping forms
func (v *Variable) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		v.Id = value.Value
		return nil
	}
	type variableAlias Variable
	return value.Decode((*variableAlias)(v))
}

// User represents a user in a policy.
type User struct {
	Statement    `yaml:"-"`
	Id           string                 `yaml:"id"`
	Owner        ResourceRef            `yaml:"owner,omitempty"`
	Annotations  map[string]interface{} `yaml:"annotations,omitempty"`
	RestrictedTo []string               `yaml:"restricted_to,omitempty"`
}

func (User) isStatement() {}

// UnmarshalYAML for User handles both scalar (just ID) and mapping forms
func (u *User) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		u.Id = value.Value
		return nil
	}
	type userAlias User
	return value.Decode((*userAlias)(u))
}

// Policy represents a policy container with nested statements.
type Policy struct {
	Statement   `yaml:"-"`
	Id          string                 `yaml:"id"`
	Annotations map[string]interface{} `yaml:"annotations,omitempty"`
	Owner       ResourceRef            `yaml:"owner,omitempty"`
	Body        Statements             `yaml:"body,omitempty"`
}

func (Policy) isStatement() {}

// Layer represents a layer in a policy.
type Layer struct {
	Statement   `yaml:"-"`
	Id          string                 `yaml:"id,omitempty"`
	Annotations map[string]interface{} `yaml:"annotations,omitempty"`
	Owner       ResourceRef            `yaml:"owner,omitempty"`
}

func (Layer) isStatement() {}

// Grant represents a role membership grant.
type Grant struct {
	Statement `yaml:"-"`
	Role      ResourceRef   `yaml:"role"`
	Member    ResourceRef   `yaml:"-"` // Use custom unmarshaler
	Members   []ResourceRef `yaml:"-"` // Plural form
}

func (Grant) isStatement() {}

// Host represents a host in a policy.
type Host struct {
	Statement    `yaml:"-"`
	Id           string                 `yaml:"id,omitempty"`
	Owner        ResourceRef            `yaml:"owner,omitempty"`
	Body         Statements             `yaml:"body,omitempty"`
	Annotations  map[string]interface{} `yaml:"annotations,omitempty"`
	RestrictedTo []string               `yaml:"restricted_to,omitempty"`
}

func (Host) isStatement() {}

// UnmarshalYAML for Host handles both scalar (just ID) and mapping forms
func (h *Host) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		h.Id = value.Value
		return nil
	}
	type hostAlias Host
	return value.Decode((*hostAlias)(h))
}

// Delete represents a delete statement.
type Delete struct {
	Statement `yaml:"-"`
	Record    ResourceRef `yaml:"record"`
}

func (Delete) isStatement() {}

// Permit represents a permission grant.
type Permit struct {
	Statement  `yaml:"-"`
	Role       ResourceRef   `yaml:"role"`
	Privileges []Privilege   `yaml:"privileges,flow"`
	Resources  []ResourceRef `yaml:"-"` // Supports both singular and plural form
}

func (Permit) isStatement() {}

// Deny represents a permission denial.
type Deny struct {
	Statement  `yaml:"-"`
	Role       ResourceRef   `yaml:"role"`
	Privileges []Privilege   `yaml:"privileges,flow"`
	Resources  []ResourceRef `yaml:"-"` // Supports both singular and plural form
}

func (Deny) isStatement() {}

// HostFactory represents a host factory.
type HostFactory struct {
	Statement   `yaml:"-"`
	Id          string                 `yaml:"id"`
	Annotations map[string]interface{} `yaml:"annotations,omitempty"`
	Owner       ResourceRef            `yaml:"owner,omitempty"`
	Layers      []ResourceRef          `yaml:"layers,omitempty"`
}

func (HostFactory) isStatement() {}

// Webservice represents a webservice.
type Webservice struct {
	Statement   `yaml:"-"`
	Id          string                 `yaml:"id"`
	Annotations map[string]interface{} `yaml:"annotations,omitempty"`
	Owner       ResourceRef            `yaml:"owner,omitempty"`
}

func (Webservice) isStatement() {}

// UnmarshalYAML for Webservice handles both scalar (just ID) and mapping forms
func (w *Webservice) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		w.Id = value.Value
		return nil
	}
	type webserviceAlias Webservice
	return value.Decode((*webserviceAlias)(w))
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

// Statements is a slice of Statement that can be unmarshaled from YAML.
type Statements []Statement

func (s *Statements) UnmarshalYAML(value *yaml.Node) error {
	var statements []Statement
	for _, node := range value.Content {
		var statement Statement

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
	return marshalYAMLWithTag(p, KindPolicy)
}

func (v Variable) MarshalYAML() (interface{}, error) {
	return marshalYAMLWithTag(v, KindVariable)
}

func (u User) MarshalYAML() (interface{}, error) {
	return marshalYAMLWithTag(u, KindUser)
}

func (g Group) MarshalYAML() (interface{}, error) {
	return marshalYAMLWithTag(g, KindGroup)
}

func (l Layer) MarshalYAML() (interface{}, error) {
	return marshalYAMLWithTag(l, KindLayer)
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
	return marshalYAMLWithTag(h, KindHost)
}

func (d Delete) MarshalYAML() (interface{}, error) {
	return marshalYAMLWithTag(d, KindDelete)
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
	return marshalYAMLWithTag(hf, KindHostFactory)
}

func (w Webservice) MarshalYAML() (interface{}, error) {
	return marshalYAMLWithTag(w, KindWebservice)
}
