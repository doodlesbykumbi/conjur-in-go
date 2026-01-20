package loader

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/policy/parser"
)

// Result contains the results of loading a policy.
type Result struct {
	CreatedRoles map[string]RoleCredentials // role_id -> credentials
	Version      int
}

// RoleCredentials contains the API key for a newly created role.
type RoleCredentials struct {
	ID     string `json:"id"`
	APIKey string `json:"api_key"`
}

// Loader handles loading policy into the database.
type Loader struct {
	store           Store
	account         string
	policyID        string // The target policy resource ID (e.g., "myorg:policy:root")
	roleID          string // The role loading the policy
	clientIP        string // Client IP address for audit
	policyText      string // Original policy text for versioning
	deletePermitted bool   // Whether !delete statements are allowed
	dryRun          bool   // If true, validate only without applying changes
}

// NewLoader creates a new policy loader.
func NewLoader(store Store, account string) *Loader {
	return &Loader{
		store:    store,
		account:  account,
		policyID: account + ":policy:root", // Default to root policy
		roleID:   account + ":user:admin",  // Default to admin
	}
}

// WithPolicyID sets the target policy ID.
func (l *Loader) WithPolicyID(policyID string) *Loader {
	l.policyID = policyID
	return l
}

// WithRoleID sets the role loading the policy.
func (l *Loader) WithRoleID(roleID string) *Loader {
	l.roleID = roleID
	return l
}

// WithClientIP sets the client IP for audit.
func (l *Loader) WithClientIP(clientIP string) *Loader {
	l.clientIP = clientIP
	return l
}

// WithDeletePermitted sets whether !delete statements are allowed.
func (l *Loader) WithDeletePermitted(permitted bool) *Loader {
	l.deletePermitted = permitted
	return l
}

// WithDryRun sets whether to validate only without applying changes.
func (l *Loader) WithDryRun(dryRun bool) *Loader {
	l.dryRun = dryRun
	return l
}

// LoadFromReader parses and loads policy from an io.Reader.
func (l *Loader) LoadFromReader(r io.Reader) (*Result, error) {
	statements, err := parser.Parse(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}

	return l.Load(statements)
}

// LoadFromString parses and loads policy from a string.
func (l *Loader) LoadFromString(policyText string) (*Result, error) {
	l.policyText = policyText
	return l.LoadFromReader(strings.NewReader(policyText))
}

// Load applies parsed policy statements to the database.
// Statements are processed in dependency order:
// 1. First pass: Create all roles and resources (User, Group, Host, Variable, Layer, Policy)
// 2. Second pass: Create relationships (Grant, Permit, Deny, Delete)
func (l *Loader) Load(statements parser.Statements) (*Result, error) {
	result := &Result{
		CreatedRoles: make(map[string]RoleCredentials),
	}

	// Separate statements into creation vs relationship statements
	var createStatements []parser.Statement
	var relationshipStatements []parser.Statement

	categorizeStatements(statements, &createStatements, &relationshipStatements)

	var policyVersion *PolicyVersion

	err := l.store.Transaction(func(txStore Store) error {
		// Create policy version record for tracking
		if l.policyText != "" && !l.dryRun {
			hash := sha256.Sum256([]byte(l.policyText))

			// Use the role ID if set, otherwise default to admin
			roleID := l.roleID
			if roleID == "" {
				roleID = l.account + ":user:admin"
			}

			policyVersion = &PolicyVersion{
				ResourceID:   l.policyID,
				RoleID:       roleID,
				CreatedAt:    time.Now(),
				PolicyText:   l.policyText,
				PolicySHA256: hex.EncodeToString(hash[:]),
				ClientIP:     l.clientIP,
			}
			if err := txStore.CreatePolicyVersion(policyVersion); err != nil {
				return err
			}
			// Refresh to get the auto-incremented version
			pv, err := txStore.GetPolicyVersion(l.policyID)
			if err != nil {
				return err
			}
			policyVersion = pv
		}

		ctx := &loadContext{
			store:           txStore,
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
	if policyVersion != nil {
		result.Version = policyVersion.Version
	}

	return result, nil
}

// categorizeStatements separates statements into creation and relationship categories.
// It recursively processes Policy bodies to extract nested statements.
func categorizeStatements(statements parser.Statements, creates *[]parser.Statement, relationships *[]parser.Statement) {
	for _, stmt := range statements {
		switch s := stmt.(type) {
		case parser.Grant, parser.Permit, parser.Deny, parser.Delete:
			*relationships = append(*relationships, stmt)
		case parser.Policy:
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

// loadContext holds state during policy loading.
type loadContext struct {
	store           Store
	account         string
	policyPath      []string // stack of policy IDs for nested policies
	createdRoles    map[string]RoleCredentials
	deletePermitted bool
}

// currentPolicyID returns the fully qualified policy ID.
func (ctx *loadContext) currentPolicyID() string {
	if len(ctx.policyPath) == 0 {
		return fmt.Sprintf("%s:policy:root", ctx.account)
	}
	return fmt.Sprintf("%s:policy:%s", ctx.account, strings.Join(ctx.policyPath, "/"))
}

// qualifyID creates a fully qualified ID for a resource/role.
// For users, Ruby Conjur uses a special '@' notation: user Dave in policy BotApp becomes Dave@BotApp
func (ctx *loadContext) qualifyID(kind, id string) string {
	var fullID string
	if len(ctx.policyPath) > 0 {
		if kind == "user" {
			// Users use @ notation: id@policy-path (with path segments joined by -)
			namespace := strings.Join(ctx.policyPath, "-")
			fullID = id + "@" + namespace
		} else {
			fullID = strings.Join(ctx.policyPath, "/") + "/" + id
		}
	} else {
		fullID = id
	}
	return fmt.Sprintf("%s:%s:%s", ctx.account, kind, fullID)
}

// resolveRef resolves a ResourceRef to a fully qualified ID.
func (ctx *loadContext) resolveRef(ref parser.ResourceRef) string {
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

// loadStatement dispatches to the appropriate handler based on statement type.
func (ctx *loadContext) loadStatement(stmt parser.Statement) error {
	switch s := stmt.(type) {
	case parser.Policy:
		return ctx.loadPolicy(s)
	case parser.User:
		return ctx.loadUser(s)
	case parser.Group:
		return ctx.loadGroup(s)
	case parser.Host:
		return ctx.loadHost(s)
	case parser.Variable:
		return ctx.loadVariable(s)
	case parser.Layer:
		return ctx.loadLayer(s)
	case parser.Grant:
		return ctx.loadGrant(s)
	case parser.Permit:
		return ctx.loadPermit(s)
	case parser.Deny:
		return ctx.loadDeny(s)
	case parser.Delete:
		return ctx.loadDelete(s)
	case parser.HostFactory:
		return ctx.loadHostFactory(s)
	case parser.Webservice:
		return ctx.loadWebservice(s)
	default:
		return fmt.Errorf("unknown statement type: %T", stmt)
	}
}

// loadPolicy loads a policy and its body.
func (ctx *loadContext) loadPolicy(p parser.Policy) error {
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

// loadUser creates a user role and resource.
func (ctx *loadContext) loadUser(u parser.User) error {
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

	if err := ctx.createCredentials(roleID, apiKey, u.RestrictedTo); err != nil {
		return err
	}

	ctx.createdRoles[roleID] = RoleCredentials{
		ID:     roleID,
		APIKey: apiKey,
	}

	return nil
}

// loadGroup creates a group role and resource.
func (ctx *loadContext) loadGroup(g parser.Group) error {
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

// loadHost creates a host role and resource with credentials.
func (ctx *loadContext) loadHost(h parser.Host) error {
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

	if err := ctx.createCredentials(roleID, apiKey, h.RestrictedTo); err != nil {
		return err
	}

	ctx.createdRoles[roleID] = RoleCredentials{
		ID:     roleID,
		APIKey: apiKey,
	}

	return nil
}

// loadVariable creates a variable resource (no role).
func (ctx *loadContext) loadVariable(v parser.Variable) error {
	resourceID := ctx.qualifyID("variable", v.Id)

	ownerID := ctx.resolveRef(v.Owner)
	if ownerID == "" {
		ownerID = ctx.currentPolicyID()
	}

	annotations := v.Annotations
	if annotations == nil {
		annotations = make(map[string]interface{})
	}
	if v.Kind != "" {
		annotations["conjur/kind"] = v.Kind
	}

	return ctx.createResource(resourceID, ownerID, annotations)
}

// loadLayer creates a layer role and resource.
func (ctx *loadContext) loadLayer(l parser.Layer) error {
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

// loadGrant creates role membership for all members.
func (ctx *loadContext) loadGrant(g parser.Grant) error {
	roleID := ctx.resolveRef(g.Role)

	// Handle multiple members
	for _, member := range g.Members {
		memberID := ctx.resolveRef(member)
		if err := ctx.store.CreateRoleMembership(roleID, memberID, false, false); err != nil {
			return err
		}
	}
	return nil
}

// loadPermit creates permission grants for all resources.
func (ctx *loadContext) loadPermit(p parser.Permit) error {
	roleID := ctx.resolveRef(p.Role)

	// Handle multiple resources
	for _, resource := range p.Resources {
		resourceID := ctx.resolveRef(resource)
		for _, priv := range p.Privileges {
			if err := ctx.store.CreatePermission(priv.String(), resourceID, roleID); err != nil {
				return err
			}
		}
	}

	return nil
}

// loadDeny removes permissions (opposite of permit) for all resources.
func (ctx *loadContext) loadDeny(d parser.Deny) error {
	roleID := ctx.resolveRef(d.Role)

	// Handle multiple resources
	for _, resource := range d.Resources {
		resourceID := ctx.resolveRef(resource)
		for _, priv := range d.Privileges {
			if err := ctx.store.DeletePermission(priv.String(), resourceID, roleID); err != nil {
				return err
			}
		}
	}

	return nil
}

// loadDelete removes a record.
func (ctx *loadContext) loadDelete(d parser.Delete) error {
	if !ctx.deletePermitted {
		return fmt.Errorf("delete statements are not permitted in this policy mode (use PUT or PATCH)")
	}

	recordID := ctx.resolveRef(d.Record)

	// Delete from resources (will cascade to permissions, annotations)
	if err := ctx.store.DeleteResource(recordID); err != nil {
		return err
	}

	// Delete from roles (will cascade to role_memberships)
	return ctx.store.DeleteRole(recordID)
}

// loadHostFactory creates a host_factory role and resource.
func (ctx *loadContext) loadHostFactory(hf parser.HostFactory) error {
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
		if err := ctx.store.CreateRoleMembership(layerID, roleID, false, false); err != nil {
			return err
		}
	}

	return nil
}

// loadWebservice creates a webservice resource (no role).
func (ctx *loadContext) loadWebservice(ws parser.Webservice) error {
	resourceID := ctx.qualifyID("webservice", ws.Id)

	ownerID := ctx.resolveRef(ws.Owner)
	if ownerID == "" {
		ownerID = ctx.currentPolicyID()
	}

	return ctx.createResource(resourceID, ownerID, ws.Annotations)
}

// createRole creates a role in the database.
func (ctx *loadContext) createRole(roleID string) error {
	return ctx.store.CreateRole(roleID)
}

// createResource creates a resource with owner and annotations.
func (ctx *loadContext) createResource(resourceID, ownerID string, annotations map[string]interface{}) error {
	return ctx.store.CreateResource(resourceID, ownerID, annotations)
}

// createCredentials creates credentials for a role with optional CIDR restrictions.
func (ctx *loadContext) createCredentials(roleID, apiKey string, restrictedTo []string) error {
	return ctx.store.CreateCredentials(roleID, apiKey, restrictedTo)
}

// generateAPIKey generates a random API key.
func generateAPIKey() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
