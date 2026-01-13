package policy

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

// PolicyVersion represents a version of a loaded policy
type PolicyVersion struct {
	ResourceID   string     `gorm:"column:resource_id;primaryKey"`
	RoleID       string     `gorm:"column:role_id"`
	Version      int        `gorm:"column:version;primaryKey"`
	CreatedAt    time.Time  `gorm:"column:created_at"`
	PolicyText   string     `gorm:"column:policy_text"`
	PolicySHA256 string     `gorm:"column:policy_sha256"`
	FinishedAt   *time.Time `gorm:"column:finished_at"`
	ClientIP     string     `gorm:"column:client_ip"`
}

func (PolicyVersion) TableName() string {
	return "policy_versions"
}

// LoadResult contains the results of loading a policy
type LoadResult struct {
	CreatedRoles map[string]RoleCredentials // role_id -> credentials
	Version      int
}

// RoleCredentials contains the API key for a newly created role
type RoleCredentials struct {
	ID     string `json:"id"`
	APIKey string `json:"api_key"`
}

// Loader handles loading policy into the database
type Loader struct {
	db              *gorm.DB
	account         string
	policyID        string // The target policy resource ID (e.g., "myorg:policy:root")
	roleID          string // The role loading the policy
	clientIP        string // Client IP address for audit
	policyText      string // Original policy text for versioning
	deletePermitted bool   // Whether !delete statements are allowed
	dryRun          bool   // If true, validate only without applying changes
}

// NewLoader creates a new policy loader
func NewLoader(db *gorm.DB, account string) *Loader {
	return &Loader{
		db:       db,
		account:  account,
		policyID: account + ":policy:root", // Default to root policy
		roleID:   account + ":user:admin",  // Default to admin
	}
}

// WithPolicyID sets the target policy ID
func (l *Loader) WithPolicyID(policyID string) *Loader {
	l.policyID = policyID
	return l
}

// WithRoleID sets the role loading the policy
func (l *Loader) WithRoleID(roleID string) *Loader {
	l.roleID = roleID
	return l
}

// WithClientIP sets the client IP for audit
func (l *Loader) WithClientIP(clientIP string) *Loader {
	l.clientIP = clientIP
	return l
}

// WithDeletePermitted sets whether !delete statements are allowed
func (l *Loader) WithDeletePermitted(permitted bool) *Loader {
	l.deletePermitted = permitted
	return l
}

// WithDryRun sets whether to validate only without applying changes
func (l *Loader) WithDryRun(dryRun bool) *Loader {
	l.dryRun = dryRun
	return l
}

// LoadFromReader parses and loads policy from an io.Reader
func (l *Loader) LoadFromReader(r io.Reader) (*LoadResult, error) {
	statements, err := Parse(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}

	return l.Load(statements)
}

// LoadFromString parses and loads policy from a string
func (l *Loader) LoadFromString(policyText string) (*LoadResult, error) {
	l.policyText = policyText
	return l.LoadFromReader(strings.NewReader(policyText))
}

// Load applies parsed policy statements to the database
// Statements are processed in dependency order:
// 1. First pass: Create all roles and resources (User, Group, Host, Variable, Layer, Policy)
// 2. Second pass: Create relationships (Grant, Permit, Deny, Delete)
func (l *Loader) Load(statements PolicyStatements) (*LoadResult, error) {
	result := &LoadResult{
		CreatedRoles: make(map[string]RoleCredentials),
	}

	// Separate statements into creation vs relationship statements
	var createStatements []Resource
	var relationshipStatements []Resource

	categorizeStatements(statements, &createStatements, &relationshipStatements)

	var policyVersion PolicyVersion

	err := l.db.Transaction(func(tx *gorm.DB) error {
		// Create policy version record for tracking
		if l.policyText != "" && !l.dryRun {
			hash := sha256.Sum256([]byte(l.policyText))

			// Use the role ID if set, otherwise default to admin
			roleID := l.roleID
			if roleID == "" {
				roleID = l.account + ":user:admin"
			}

			policyVersion = PolicyVersion{
				ResourceID:   l.policyID,
				RoleID:       roleID,
				CreatedAt:    time.Now(),
				PolicyText:   l.policyText,
				PolicySHA256: hex.EncodeToString(hash[:]),
				ClientIP:     l.clientIP,
			}
			// Version is auto-incremented by database trigger
			if err := tx.Create(&policyVersion).Error; err != nil {
				return fmt.Errorf("failed to create policy version: %w", err)
			}
			// Refresh to get the auto-incremented version
			if err := tx.Where("resource_id = ? AND finished_at IS NULL", l.policyID).First(&policyVersion).Error; err != nil {
				return fmt.Errorf("failed to get policy version: %w", err)
			}
		}

		ctx := &loadContext{
			db:              tx,
			account:         l.account,
			createdRoles:    result.CreatedRoles,
			deletePermitted: l.deletePermitted,
		}

		// First pass: create all roles and resources
		for _, stmt := range createStatements {
			if err := ctx.loadStatement(stmt); err != nil {
				return err
			}
		}

		// Second pass: create relationships (grants, permits, etc.)
		for _, stmt := range relationshipStatements {
			if err := ctx.loadStatement(stmt); err != nil {
				return err
			}
		}

		// For dry-run, rollback the transaction by returning an error
		if l.dryRun {
			return fmt.Errorf("DRY_RUN_ROLLBACK")
		}

		return nil
	})

	// For dry-run, the error is expected - we use it to rollback
	if err != nil && l.dryRun && err.Error() == "DRY_RUN_ROLLBACK" {
		// Dry-run successful - policy is valid
		return result, nil
	}

	if err != nil {
		return nil, err
	}

	// Set the version from the created policy version record
	result.Version = policyVersion.Version

	return result, nil
}

// categorizeStatements separates statements into creation and relationship categories
// It recursively processes Policy bodies to extract nested statements
func categorizeStatements(statements PolicyStatements, creates *[]Resource, relationships *[]Resource) {
	for _, stmt := range statements {
		switch s := stmt.(type) {
		case Grant, Permit, Deny, Delete:
			*relationships = append(*relationships, stmt)
		case Policy:
			// Policy itself is a create statement
			*creates = append(*creates, stmt)
			// But we also need to categorize its body
			categorizeStatements(s.Body, creates, relationships)
		default:
			// User, Group, Host, Variable, Layer are all create statements
			*creates = append(*creates, stmt)
		}
	}
}

// loadContext holds state during policy loading
type loadContext struct {
	db              *gorm.DB
	account         string
	policyPath      []string // stack of policy IDs for nested policies
	createdRoles    map[string]RoleCredentials
	deletePermitted bool
}

// currentPolicyID returns the fully qualified policy ID
func (ctx *loadContext) currentPolicyID() string {
	if len(ctx.policyPath) == 0 {
		return fmt.Sprintf("%s:policy:root", ctx.account)
	}
	return fmt.Sprintf("%s:policy:%s", ctx.account, strings.Join(ctx.policyPath, "/"))
}

// qualifyID creates a fully qualified ID for a resource/role
func (ctx *loadContext) qualifyID(kind, id string) string {
	var fullID string
	if len(ctx.policyPath) > 0 {
		fullID = strings.Join(ctx.policyPath, "/") + "/" + id
	} else {
		fullID = id
	}
	return fmt.Sprintf("%s:%s:%s", ctx.account, kind, fullID)
}

// resolveRef resolves a ResourceRef to a fully qualified ID
func (ctx *loadContext) resolveRef(ref ResourceRef) string {
	if ref.Id == "" {
		return ""
	}
	// If the ref already contains account prefix, use as-is
	if strings.Contains(ref.Id, ":") {
		return ref.Id
	}
	// Otherwise qualify with current context
	return ctx.qualifyID(ref.Kind.String(), ref.Id)
}

// loadStatement dispatches to the appropriate handler based on statement type
func (ctx *loadContext) loadStatement(stmt Resource) error {
	switch s := stmt.(type) {
	case Policy:
		return ctx.loadPolicy(s)
	case User:
		return ctx.loadUser(s)
	case Group:
		return ctx.loadGroup(s)
	case Host:
		return ctx.loadHost(s)
	case Variable:
		return ctx.loadVariable(s)
	case Layer:
		return ctx.loadLayer(s)
	case Grant:
		return ctx.loadGrant(s)
	case Permit:
		return ctx.loadPermit(s)
	case Deny:
		return ctx.loadDeny(s)
	case Delete:
		return ctx.loadDelete(s)
	case HostFactory:
		return ctx.loadHostFactory(s)
	case Webservice:
		return ctx.loadWebservice(s)
	default:
		return fmt.Errorf("unknown statement type: %T", stmt)
	}
}

// loadPolicy loads a policy and its body
func (ctx *loadContext) loadPolicy(p Policy) error {
	// Push policy onto path
	ctx.policyPath = append(ctx.policyPath, p.Id)
	defer func() {
		ctx.policyPath = ctx.policyPath[:len(ctx.policyPath)-1]
	}()

	policyID := ctx.currentPolicyID()
	roleID := policyID // policies are both roles and resources

	// Determine owner
	ownerID := ctx.resolveRef(p.Owner)
	if ownerID == "" {
		// Default owner is the parent policy or admin
		if len(ctx.policyPath) > 1 {
			parentPath := ctx.policyPath[:len(ctx.policyPath)-1]
			ownerID = fmt.Sprintf("%s:policy:%s", ctx.account, strings.Join(parentPath, "/"))
		} else {
			ownerID = fmt.Sprintf("%s:user:admin", ctx.account)
		}
	}

	// Create role for policy
	if err := ctx.createRole(roleID); err != nil {
		return err
	}

	// Create resource for policy
	if err := ctx.createResource(policyID, ownerID, p.Annotations); err != nil {
		return err
	}

	// Load body statements
	for _, stmt := range p.Body {
		if err := ctx.loadStatement(stmt); err != nil {
			return err
		}
	}

	return nil
}

// loadUser creates a user role and resource
func (ctx *loadContext) loadUser(u User) error {
	roleID := ctx.qualifyID("user", u.Id)
	resourceID := roleID

	ownerID := ctx.resolveRef(u.Owner)
	if ownerID == "" {
		ownerID = ctx.currentPolicyID()
	}

	if err := ctx.createRole(roleID); err != nil {
		return err
	}

	if err := ctx.createResource(resourceID, ownerID, u.Annotations); err != nil {
		return err
	}

	// Generate API key for user
	apiKey, err := generateAPIKey()
	if err != nil {
		return err
	}

	if err := ctx.createCredentials(roleID, apiKey); err != nil {
		return err
	}

	ctx.createdRoles[roleID] = RoleCredentials{
		ID:     roleID,
		APIKey: apiKey,
	}

	return nil
}

// loadGroup creates a group role and resource
func (ctx *loadContext) loadGroup(g Group) error {
	roleID := ctx.qualifyID("group", g.Id)
	resourceID := roleID

	ownerID := ctx.resolveRef(g.Owner)
	if ownerID == "" {
		ownerID = ctx.currentPolicyID()
	}

	if err := ctx.createRole(roleID); err != nil {
		return err
	}

	return ctx.createResource(resourceID, ownerID, g.Annotations)
}

// loadHost creates a host role and resource with credentials
func (ctx *loadContext) loadHost(h Host) error {
	roleID := ctx.qualifyID("host", h.Id)
	resourceID := roleID

	ownerID := ctx.resolveRef(h.Owner)
	if ownerID == "" {
		ownerID = ctx.currentPolicyID()
	}

	if err := ctx.createRole(roleID); err != nil {
		return err
	}

	if err := ctx.createResource(resourceID, ownerID, h.Annotations); err != nil {
		return err
	}

	// Generate API key for host
	apiKey, err := generateAPIKey()
	if err != nil {
		return err
	}

	if err := ctx.createCredentials(roleID, apiKey); err != nil {
		return err
	}

	ctx.createdRoles[roleID] = RoleCredentials{
		ID:     roleID,
		APIKey: apiKey,
	}

	return nil
}

// loadVariable creates a variable resource (no role)
func (ctx *loadContext) loadVariable(v Variable) error {
	resourceID := ctx.qualifyID("variable", v.Id)

	// Variables don't have explicit owners in the struct, use current policy
	ownerID := ctx.currentPolicyID()

	annotations := v.Annotations
	if annotations == nil {
		annotations = make(map[string]interface{})
	}
	if v.Kind != "" {
		annotations["conjur/kind"] = v.Kind
	}

	return ctx.createResource(resourceID, ownerID, annotations)
}

// loadLayer creates a layer role and resource
func (ctx *loadContext) loadLayer(l Layer) error {
	roleID := ctx.qualifyID("layer", l.Id)
	resourceID := roleID

	ownerID := ctx.resolveRef(l.Owner)
	if ownerID == "" {
		ownerID = ctx.currentPolicyID()
	}

	if err := ctx.createRole(roleID); err != nil {
		return err
	}

	return ctx.createResource(resourceID, ownerID, l.Annotations)
}

// loadGrant creates role membership for all members
func (ctx *loadContext) loadGrant(g Grant) error {
	roleID := ctx.resolveRef(g.Role)

	// Handle multiple members
	for _, member := range g.Members {
		memberID := ctx.resolveRef(member)
		err := ctx.db.Exec(`
			INSERT INTO role_memberships (role_id, member_id, admin_option, ownership)
			VALUES (?, ?, false, false)
			ON CONFLICT DO NOTHING
		`, roleID, memberID).Error
		if err != nil {
			return err
		}
	}
	return nil
}

// loadPermit creates permission grants for all resources
func (ctx *loadContext) loadPermit(p Permit) error {
	roleID := ctx.resolveRef(p.Role)

	// Handle multiple resources
	for _, resource := range p.Resources {
		resourceID := ctx.resolveRef(resource)
		for _, priv := range p.Privileges {
			err := ctx.db.Exec(`
				INSERT INTO permissions (privilege, resource_id, role_id)
				VALUES (?, ?, ?)
				ON CONFLICT DO NOTHING
			`, priv.String(), resourceID, roleID).Error
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// loadDeny removes permissions (opposite of permit) for all resources
func (ctx *loadContext) loadDeny(d Deny) error {
	roleID := ctx.resolveRef(d.Role)

	// Handle multiple resources
	for _, resource := range d.Resources {
		resourceID := ctx.resolveRef(resource)
		for _, priv := range d.Privileges {
			err := ctx.db.Exec(`
				DELETE FROM permissions 
				WHERE privilege = ? AND resource_id = ? AND role_id = ?
			`, priv.String(), resourceID, roleID).Error
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// loadDelete removes a record
func (ctx *loadContext) loadDelete(d Delete) error {
	if !ctx.deletePermitted {
		return fmt.Errorf("delete statements are not permitted in this policy mode (use PUT or PATCH)")
	}

	recordID := ctx.resolveRef(d.Record)

	// Delete from resources (will cascade to permissions, annotations)
	if err := ctx.db.Exec(`DELETE FROM resources WHERE resource_id = ?`, recordID).Error; err != nil {
		return err
	}

	// Delete from roles (will cascade to role_memberships)
	return ctx.db.Exec(`DELETE FROM roles WHERE role_id = ?`, recordID).Error
}

// loadHostFactory creates a host_factory role and resource
func (ctx *loadContext) loadHostFactory(hf HostFactory) error {
	roleID := ctx.qualifyID("host_factory", hf.Id)
	resourceID := roleID

	ownerID := ctx.resolveRef(hf.Owner)
	if ownerID == "" {
		ownerID = ctx.currentPolicyID()
	}

	if err := ctx.createRole(roleID); err != nil {
		return err
	}

	if err := ctx.createResource(resourceID, ownerID, hf.Annotations); err != nil {
		return err
	}

	// Add layer memberships for the host factory
	for _, layer := range hf.Layers {
		layerID := ctx.resolveRef(layer)
		err := ctx.db.Exec(`
			INSERT INTO role_memberships (role_id, member_id, admin_option, ownership)
			VALUES (?, ?, false, false)
			ON CONFLICT DO NOTHING
		`, layerID, roleID).Error
		if err != nil {
			return err
		}
	}

	return nil
}

// loadWebservice creates a webservice resource (no role)
func (ctx *loadContext) loadWebservice(ws Webservice) error {
	resourceID := ctx.qualifyID("webservice", ws.Id)

	ownerID := ctx.resolveRef(ws.Owner)
	if ownerID == "" {
		ownerID = ctx.currentPolicyID()
	}

	return ctx.createResource(resourceID, ownerID, ws.Annotations)
}

// createRole creates a role in the database
func (ctx *loadContext) createRole(roleID string) error {
	return ctx.db.Exec(`
		INSERT INTO roles (role_id) VALUES (?)
		ON CONFLICT (role_id) DO NOTHING
	`, roleID).Error
}

// createResource creates a resource with owner and annotations
func (ctx *loadContext) createResource(resourceID, ownerID string, annotations map[string]interface{}) error {
	err := ctx.db.Exec(`
		INSERT INTO resources (resource_id, owner_id) VALUES (?, ?)
		ON CONFLICT (resource_id) DO UPDATE SET owner_id = EXCLUDED.owner_id
	`, resourceID, ownerID).Error
	if err != nil {
		return err
	}

	// Add annotations
	for name, value := range annotations {
		err := ctx.db.Exec(`
			INSERT INTO annotations (resource_id, name, value) VALUES (?, ?, ?)
			ON CONFLICT (resource_id, name) DO UPDATE SET value = EXCLUDED.value
		`, resourceID, name, fmt.Sprintf("%v", value)).Error
		if err != nil {
			return err
		}
	}

	return nil
}

// createCredentials creates credentials for a role
func (ctx *loadContext) createCredentials(roleID, apiKey string) error {
	return ctx.db.Exec(`
		INSERT INTO credentials (role_id, api_key) VALUES (?, ?)
		ON CONFLICT (role_id) DO UPDATE SET api_key = EXCLUDED.api_key
	`, roleID, []byte(apiKey)).Error
}

// generateAPIKey generates a random API key
func generateAPIKey() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// Parse parses policy YAML from a reader
func Parse(r io.Reader) (PolicyStatements, error) {
	var statements PolicyStatements
	decoder := yaml.NewDecoder(r)
	if err := decoder.Decode(&statements); err != nil {
		return nil, err
	}
	return statements, nil
}
