package endpoints

import (
	"github.com/stretchr/testify/mock"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/model"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"
)

// MockSecretsStore implements store.SecretsStore for testing using testify/mock
type MockSecretsStore struct {
	mock.Mock
}

func NewMockSecretsStore() *MockSecretsStore {
	return &MockSecretsStore{}
}

func (m *MockSecretsStore) FetchSecret(resourceID string, version string) (*store.Secret, error) {
	args := m.Called(resourceID, version)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*store.Secret), args.Error(1)
}

func (m *MockSecretsStore) CreateSecret(resourceID string, value []byte) error {
	args := m.Called(resourceID, value)
	return args.Error(0)
}

func (m *MockSecretsStore) ExpireSecret(resourceID string) error {
	args := m.Called(resourceID)
	return args.Error(0)
}

func (m *MockSecretsStore) FetchSecretsWithPrefix(prefix string) ([]store.Secret, error) {
	args := m.Called(prefix)
	return args.Get(0).([]store.Secret), args.Error(1)
}

// MockAuthzStore implements store.AuthzStore for testing using testify/mock
type MockAuthzStore struct {
	mock.Mock
}

func NewMockAuthzStore() *MockAuthzStore {
	return &MockAuthzStore{}
}

func (m *MockAuthzStore) IsRoleAllowedTo(roleID, privilege, resourceID string) bool {
	args := m.Called(roleID, privilege, resourceID)
	return args.Bool(0)
}

func (m *MockAuthzStore) IsResourceVisible(resourceID, roleID string) bool {
	args := m.Called(resourceID, roleID)
	return args.Bool(0)
}

// MockResourcesStore implements store.ResourcesStore for testing using testify/mock
type MockResourcesStore struct {
	mock.Mock
}

func NewMockResourcesStore() *MockResourcesStore {
	return &MockResourcesStore{}
}

func (m *MockResourcesStore) ListResources(account, kind, roleID, search string, limit, offset int) []store.Resource {
	args := m.Called(account, kind, roleID, search, limit, offset)
	return args.Get(0).([]store.Resource)
}

func (m *MockResourcesStore) CountResources(account, kind, roleID, search string) int {
	args := m.Called(account, kind, roleID, search)
	return args.Int(0)
}

func (m *MockResourcesStore) FetchResource(resourceID string) *store.Resource {
	args := m.Called(resourceID)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*store.Resource)
}

func (m *MockResourcesStore) IsResourceVisible(resourceID, roleID string) bool {
	args := m.Called(resourceID, roleID)
	return args.Bool(0)
}

func (m *MockResourcesStore) ResourceExists(resourceID string) bool {
	args := m.Called(resourceID)
	return args.Bool(0)
}

func (m *MockResourcesStore) RoleExists(roleID string) bool {
	args := m.Called(roleID)
	return args.Bool(0)
}

func (m *MockResourcesStore) PermittedRoles(privilege, resourceID string) []string {
	args := m.Called(privilege, resourceID)
	return args.Get(0).([]string)
}

func (m *MockResourcesStore) ResourceExistsWithPrefix(prefix string) bool {
	args := m.Called(prefix)
	return args.Bool(0)
}

// MockAuthenticateStore implements store.AuthenticateStore for testing using testify/mock
type MockAuthenticateStore struct {
	mock.Mock
}

func NewMockAuthenticateStore() *MockAuthenticateStore {
	return &MockAuthenticateStore{}
}

func (m *MockAuthenticateStore) GetCredential(roleID string) (*model.Credential, error) {
	args := m.Called(roleID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Credential), args.Error(1)
}

func (m *MockAuthenticateStore) ValidateAPIKey(credential *model.Credential, apiKey []byte) bool {
	args := m.Called(credential, apiKey)
	return args.Bool(0)
}

func (m *MockAuthenticateStore) RotateAPIKey(roleID string) ([]byte, error) {
	args := m.Called(roleID)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockAuthenticateStore) UpdatePassword(roleID string, newPassword []byte) error {
	args := m.Called(roleID, newPassword)
	return args.Error(0)
}

// MockPolicyStore implements store.PolicyStore for testing using testify/mock
type MockPolicyStore struct {
	mock.Mock
}

func NewMockPolicyStore() *MockPolicyStore {
	return &MockPolicyStore{}
}

func (m *MockPolicyStore) GetPolicyVersion(policyID string, version int) (*store.PolicyVersion, error) {
	args := m.Called(policyID, version)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*store.PolicyVersion), args.Error(1)
}

func (m *MockPolicyStore) ListPolicyVersions(policyID string) []store.PolicyVersion {
	args := m.Called(policyID)
	return args.Get(0).([]store.PolicyVersion)
}
