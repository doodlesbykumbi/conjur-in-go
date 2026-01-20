package loader

import (
	"fmt"
	"net"
	"strings"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/model"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Ensure GormStore implements Store
var _ Store = (*GormStore)(nil)

// GormStore implements Store using GORM for database operations.
type GormStore struct {
	db     *gorm.DB
	cipher slosilo.SymmetricCipher
}

// NewGormStore creates a new GormStore.
func NewGormStore(db *gorm.DB, cipher slosilo.SymmetricCipher) *GormStore {
	return &GormStore{db: db, cipher: cipher}
}

// Transaction wraps operations in a database transaction.
func (s *GormStore) Transaction(fn func(Store) error) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		txStore := &GormStore{db: tx, cipher: s.cipher}
		return fn(txStore)
	})
}

// CreatePolicyVersion creates a policy version record.
func (s *GormStore) CreatePolicyVersion(pv *PolicyVersion) error {
	modelPV := model.PolicyVersion{
		ResourceID:   pv.ResourceID,
		RoleID:       pv.RoleID,
		CreatedAt:    pv.CreatedAt,
		PolicyText:   pv.PolicyText,
		PolicySHA256: pv.PolicySHA256,
		ClientIP:     pv.ClientIP,
	}
	if err := s.db.Create(&modelPV).Error; err != nil {
		return fmt.Errorf("failed to create policy version: %w", err)
	}
	// Copy back auto-generated fields
	pv.Version = modelPV.Version
	return nil
}

// GetPolicyVersion retrieves the current (unfinished) policy version for a resource.
func (s *GormStore) GetPolicyVersion(resourceID string) (*PolicyVersion, error) {
	var modelPV model.PolicyVersion
	if err := s.db.Where("resource_id = ? AND finished_at IS NULL", resourceID).First(&modelPV).Error; err != nil {
		return nil, fmt.Errorf("failed to get policy version: %w", err)
	}
	return &PolicyVersion{
		ResourceID:   modelPV.ResourceID,
		RoleID:       modelPV.RoleID,
		Version:      modelPV.Version,
		CreatedAt:    modelPV.CreatedAt,
		FinishedAt:   modelPV.FinishedAt,
		PolicyText:   modelPV.PolicyText,
		PolicySHA256: modelPV.PolicySHA256,
		ClientIP:     modelPV.ClientIP,
	}, nil
}

// CreateRole creates a role with the given ID.
func (s *GormStore) CreateRole(roleID string) error {
	role := model.Role{RoleID: roleID}
	return s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&role).Error
}

// CreateResource creates a resource with owner and annotations.
func (s *GormStore) CreateResource(resourceID, ownerID string, annotations map[string]interface{}) error {
	resource := model.Resource{ResourceID: resourceID, OwnerID: ownerID}
	err := s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "resource_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"owner_id"}),
	}).Create(&resource).Error
	if err != nil {
		return err
	}

	// Add annotations
	for name, value := range annotations {
		annotation := model.Annotation{
			ResourceID: resourceID,
			Name:       name,
			Value:      fmt.Sprintf("%v", value),
		}
		err := s.db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "resource_id"}, {Name: "name"}},
			DoUpdates: clause.AssignmentColumns([]string{"value"}),
		}).Create(&annotation).Error
		if err != nil {
			return err
		}
	}

	return nil
}

// CreateCredentials creates credentials for a role with optional CIDR restrictions.
func (s *GormStore) CreateCredentials(roleID, apiKey string, restrictedTo []string) error {
	// Encrypt the API key before storing
	encryptedAPIKey, err := s.cipher.Encrypt([]byte(roleID), []byte(apiKey))
	if err != nil {
		return fmt.Errorf("failed to encrypt API key: %w", err)
	}

	// Normalize CIDR values (add /32 for single IPs)
	normalizedCIDRs := normalizeCIDRs(restrictedTo)

	// Use raw SQL for credentials due to GORM issues with sql.RawBytes and OnConflict
	// For PostgreSQL cidr[] type, we need to format as a literal array with quoted values
	var restrictedToSQL string
	if len(normalizedCIDRs) == 0 {
		restrictedToSQL = "{}"
	} else {
		// Quote each CIDR value for PostgreSQL array literal
		quoted := make([]string, len(normalizedCIDRs))
		for i, cidr := range normalizedCIDRs {
			quoted[i] = "\"" + cidr + "\""
		}
		restrictedToSQL = "{" + strings.Join(quoted, ",") + "}"
	}

	return s.db.Exec(`
		INSERT INTO credentials (role_id, api_key, restricted_to) VALUES (?, ?, ?::cidr[])
		ON CONFLICT (role_id) DO UPDATE SET api_key = EXCLUDED.api_key, restricted_to = EXCLUDED.restricted_to
	`, roleID, encryptedAPIKey, restrictedToSQL).Error
}

// CreateRoleMembership creates a membership relationship between a role and member.
func (s *GormStore) CreateRoleMembership(roleID, memberID string, adminOption, ownership bool) error {
	membership := model.RoleMembership{
		RoleID:      roleID,
		MemberID:    memberID,
		AdminOption: adminOption,
		Ownership:   ownership,
	}
	return s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&membership).Error
}

// CreatePermission grants a privilege on a resource to a role.
func (s *GormStore) CreatePermission(privilege, resourceID, roleID string) error {
	perm := model.Permission{
		Privilege:  privilege,
		ResourceID: resourceID,
		RoleID:     roleID,
	}
	return s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&perm).Error
}

// DeletePermission removes a privilege on a resource from a role.
func (s *GormStore) DeletePermission(privilege, resourceID, roleID string) error {
	return s.db.Where("privilege = ? AND resource_id = ? AND role_id = ?",
		privilege, resourceID, roleID).Delete(&model.Permission{}).Error
}

// DeleteResource removes a resource and its associated data.
func (s *GormStore) DeleteResource(resourceID string) error {
	return s.db.Where("resource_id = ?", resourceID).Delete(&model.Resource{}).Error
}

// DeleteRole removes a role and its associated data.
func (s *GormStore) DeleteRole(roleID string) error {
	return s.db.Where("role_id = ?", roleID).Delete(&model.Role{}).Error
}

// normalizeCIDRs normalizes CIDR values (adds /32 for single IPv4 addresses).
func normalizeCIDRs(cidrs []string) []string {
	if len(cidrs) == 0 {
		return []string{}
	}
	result := make([]string, 0, len(cidrs))
	for _, cidr := range cidrs {
		// If it doesn't contain a slash, assume it's a single IP
		if !strings.Contains(cidr, "/") {
			// Check if IPv4 or IPv6
			ip := net.ParseIP(cidr)
			if ip != nil {
				if ip.To4() != nil {
					cidr = cidr + "/32"
				} else {
					cidr = cidr + "/128"
				}
			}
		}
		result = append(result, cidr)
	}
	return result
}
