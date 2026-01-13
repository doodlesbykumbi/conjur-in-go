package integration

import (
	"bytes"
	"conjur-in-go/pkg/slosilo"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/cucumber/godog"
)

// StepsContext holds state shared between step definitions
type StepsContext struct {
	tc           *TestContext
	response     *http.Response
	responseBody []byte
	authToken    string
	account      string
	adminAPIKey  string
	hostAPIKeys  map[string]string
}

// NewStepsContext creates a new steps context
func NewStepsContext(tc *TestContext) *StepsContext {
	return &StepsContext{
		tc:          tc,
		hostAPIKeys: make(map[string]string),
	}
}

// RegisterSteps registers all step definitions
func (s *StepsContext) RegisterSteps(sc *godog.ScenarioContext) {
	// Background steps
	sc.Step(`^a Conjur server is running$`, s.aConjurServerIsRunning)
	sc.Step(`^an account "([^"]*)" exists with admin user$`, s.anAccountExistsWithAdminUser)
	sc.Step(`^I am authenticated as "([^"]*)" in account "([^"]*)"$`, s.iAmAuthenticatedAs)

	// Authentication steps
	sc.Step(`^I authenticate as "([^"]*)" in account "([^"]*)" with the correct API key$`, s.iAuthenticateWithCorrectAPIKey)
	sc.Step(`^I authenticate as "([^"]*)" in account "([^"]*)" with API key "([^"]*)"$`, s.iAuthenticateWithAPIKey)
	sc.Step(`^a host "([^"]*)" exists in account "([^"]*)"$`, s.aHostExistsInAccount)

	// Response steps
	sc.Step(`^the response status should be (\d+)$`, s.theResponseStatusShouldBe)
	sc.Step(`^I should receive a valid JWT token$`, s.iShouldReceiveAValidJWTToken)
	sc.Step(`^the response body should be "([^"]*)"$`, s.theResponseBodyShouldBe)

	// Variable/Secret steps
	sc.Step(`^a variable "([^"]*)" exists in account "([^"]*)"$`, s.aVariableExistsInAccount)
	sc.Step(`^I have "([^"]*)" permission on "([^"]*)"$`, s.iHavePermissionOn)
	sc.Step(`^I store the value "([^"]*)" in variable "([^"]*)"$`, s.iStoreValueInVariable)
	sc.Step(`^I retrieve the variable "([^"]*)"$`, s.iRetrieveVariable)
	sc.Step(`^the variable "([^"]*)" has value "([^"]*)"$`, s.theVariableHasValue)
	sc.Step(`^I batch retrieve variables "([^"]*)"$`, s.iBatchRetrieveVariables)
	sc.Step(`^the response should contain secret "([^"]*)" with value "([^"]*)"$`, s.theResponseShouldContainSecret)

	// Policy steps
	sc.Step(`^I load the following policy to "([^"]*)":$`, s.iLoadPolicyTo)
	sc.Step(`^I validate the following policy for "([^"]*)":$`, s.iValidatePolicyFor)
	sc.Step(`^the policy version should be greater than (\d+)$`, s.thePolicyVersionShouldBeGreaterThan)
	sc.Step(`^user "([^"]*)" should exist in account "([^"]*)"$`, s.userShouldExistInAccount)
	sc.Step(`^user "([^"]*)" should not exist in account "([^"]*)"$`, s.userShouldNotExistInAccount)
	sc.Step(`^group "([^"]*)" should exist in account "([^"]*)"$`, s.groupShouldExistInAccount)
	sc.Step(`^variable "([^"]*)" should exist in account "([^"]*)"$`, s.variableShouldExistInAccount)
	sc.Step(`^the response should indicate dry-run mode$`, s.theResponseShouldIndicateDryRunMode)
}

// Background steps

func (s *StepsContext) aConjurServerIsRunning() error {
	// Server is already running via TestContext
	return nil
}

func (s *StepsContext) anAccountExistsWithAdminUser(account string) error {
	s.account = account
	s.adminAPIKey = "test-admin-api-key-" + account

	// Create signing key
	key, err := slosilo.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	keyBytes, err := key.Serialize()
	if err != nil {
		return err
	}

	keyId := "authn:" + account
	encryptedKey, err := s.tc.Cipher.Encrypt([]byte(keyId), keyBytes)
	if err != nil {
		return err
	}

	// Insert signing key
	if err := s.tc.DB.Exec(`
		INSERT INTO slosilo_keystore (id, key, fingerprint) VALUES (?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET key = EXCLUDED.key, fingerprint = EXCLUDED.fingerprint
	`, keyId, encryptedKey, key.Fingerprint()).Error; err != nil {
		return err
	}

	// Create admin role
	adminRoleId := account + ":user:admin"
	if err := s.tc.DB.Exec(`INSERT INTO roles (role_id) VALUES (?) ON CONFLICT DO NOTHING`, adminRoleId).Error; err != nil {
		return err
	}

	// Create admin resource
	if err := s.tc.DB.Exec(`
		INSERT INTO resources (resource_id, owner_id) VALUES (?, ?)
		ON CONFLICT DO NOTHING
	`, adminRoleId, adminRoleId).Error; err != nil {
		return err
	}

	// Encrypt and store API key
	encryptedAPIKey, err := s.tc.Cipher.Encrypt([]byte(adminRoleId), []byte(s.adminAPIKey))
	if err != nil {
		return err
	}

	if err := s.tc.DB.Exec(`
		INSERT INTO credentials (role_id, api_key) VALUES (?, ?)
		ON CONFLICT (role_id) DO UPDATE SET api_key = EXCLUDED.api_key
	`, adminRoleId, encryptedAPIKey).Error; err != nil {
		return err
	}

	// Create root policy
	policyRoleId := account + ":policy:root"
	if err := s.tc.DB.Exec(`INSERT INTO roles (role_id) VALUES (?) ON CONFLICT DO NOTHING`, policyRoleId).Error; err != nil {
		return err
	}

	return s.tc.DB.Exec(`
		INSERT INTO resources (resource_id, owner_id) VALUES (?, ?)
		ON CONFLICT DO NOTHING
	`, policyRoleId, adminRoleId).Error
}

func (s *StepsContext) iAmAuthenticatedAs(login, account string) error {
	return s.iAuthenticateWithCorrectAPIKey(login, account)
}

// Authentication steps

func (s *StepsContext) iAuthenticateWithCorrectAPIKey(login, account string) error {
	apiKey := s.adminAPIKey
	if strings.HasPrefix(login, "host/") {
		hostName := strings.TrimPrefix(login, "host/")
		apiKey = s.hostAPIKeys[hostName]
	}
	return s.iAuthenticateWithAPIKey(login, account, apiKey)
}

func (s *StepsContext) iAuthenticateWithAPIKey(login, account, apiKey string) error {
	encodedLogin := url.PathEscape(login)
	reqURL := fmt.Sprintf("%s/authn/%s/%s/authenticate", s.tc.ServerURL, account, encodedLogin)
	req, err := http.NewRequest("POST", reqURL, strings.NewReader(apiKey))
	if err != nil {
		return err
	}

	s.response, err = s.tc.HTTPClient.Do(req)
	if err != nil {
		return err
	}

	s.responseBody, err = io.ReadAll(s.response.Body)
	_ = s.response.Body.Close()
	if err != nil {
		return err
	}

	// If successful, extract token
	if s.response.StatusCode == http.StatusOK {
		var token map[string]string
		if err := json.Unmarshal(s.responseBody, &token); err == nil {
			tokenJSON, _ := json.Marshal(token)
			s.authToken = base64.URLEncoding.EncodeToString(tokenJSON)
		}
	}

	return nil
}

func (s *StepsContext) aHostExistsInAccount(hostName, account string) error {
	hostRoleId := account + ":host:" + hostName
	hostAPIKey := "host-api-key-" + hostName
	s.hostAPIKeys[hostName] = hostAPIKey

	// Create host role
	if err := s.tc.DB.Exec(`INSERT INTO roles (role_id) VALUES (?) ON CONFLICT DO NOTHING`, hostRoleId).Error; err != nil {
		return err
	}

	// Create host resource
	adminRoleId := account + ":user:admin"
	if err := s.tc.DB.Exec(`
		INSERT INTO resources (resource_id, owner_id) VALUES (?, ?)
		ON CONFLICT DO NOTHING
	`, hostRoleId, adminRoleId).Error; err != nil {
		return err
	}

	// Encrypt and store API key
	encryptedAPIKey, err := s.tc.Cipher.Encrypt([]byte(hostRoleId), []byte(hostAPIKey))
	if err != nil {
		return err
	}

	return s.tc.DB.Exec(`
		INSERT INTO credentials (role_id, api_key) VALUES (?, ?)
		ON CONFLICT (role_id) DO UPDATE SET api_key = EXCLUDED.api_key
	`, hostRoleId, encryptedAPIKey).Error
}

// Response steps

func (s *StepsContext) theResponseStatusShouldBe(expectedStatus int) error {
	if s.response.StatusCode != expectedStatus {
		return fmt.Errorf("expected status %d, got %d: %s", expectedStatus, s.response.StatusCode, string(s.responseBody))
	}
	return nil
}

func (s *StepsContext) iShouldReceiveAValidJWTToken() error {
	var token map[string]string
	if err := json.Unmarshal(s.responseBody, &token); err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	if token["protected"] == "" {
		return fmt.Errorf("missing 'protected' field in token")
	}
	if token["payload"] == "" {
		return fmt.Errorf("missing 'payload' field in token")
	}
	if token["signature"] == "" {
		return fmt.Errorf("missing 'signature' field in token")
	}

	return nil
}

func (s *StepsContext) theResponseBodyShouldBe(expected string) error {
	actual := strings.TrimSpace(string(s.responseBody))
	if actual != expected {
		return fmt.Errorf("expected body %q, got %q", expected, actual)
	}
	return nil
}

// Variable/Secret steps

func (s *StepsContext) aVariableExistsInAccount(variableId, account string) error {
	resourceId := account + ":variable:" + variableId

	// For "restricted" variables, use a different owner to test permission denial
	ownerRoleId := account + ":user:admin"
	if strings.Contains(variableId, "restricted") {
		// Create a separate owner role for restricted resources
		otherOwner := account + ":user:other-owner"
		_ = s.tc.DB.Exec(`INSERT INTO roles (role_id) VALUES (?) ON CONFLICT DO NOTHING`, otherOwner)
		_ = s.tc.DB.Exec(`INSERT INTO resources (resource_id, owner_id) VALUES (?, ?) ON CONFLICT DO NOTHING`, otherOwner, otherOwner)
		ownerRoleId = otherOwner
	}

	return s.tc.DB.Exec(`
		INSERT INTO resources (resource_id, owner_id) VALUES (?, ?)
		ON CONFLICT DO NOTHING
	`, resourceId, ownerRoleId).Error
}

func (s *StepsContext) iHavePermissionOn(privilege, resourceId string) error {
	roleId := s.account + ":user:admin"
	return s.tc.DB.Exec(`
		INSERT INTO permissions (privilege, resource_id, role_id) VALUES (?, ?, ?)
		ON CONFLICT DO NOTHING
	`, privilege, resourceId, roleId).Error
}

func (s *StepsContext) iStoreValueInVariable(value, variableId string) error {
	url := fmt.Sprintf("%s/secrets/%s/variable/%s", s.tc.ServerURL, s.account, variableId)
	req, err := http.NewRequest("POST", url, strings.NewReader(value))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", `Token token="`+s.authToken+`"`)

	s.response, err = s.tc.HTTPClient.Do(req)
	if err != nil {
		return err
	}

	s.responseBody, err = io.ReadAll(s.response.Body)
	_ = s.response.Body.Close()
	return err
}

func (s *StepsContext) iRetrieveVariable(variableId string) error {
	url := fmt.Sprintf("%s/secrets/%s/variable/%s", s.tc.ServerURL, s.account, variableId)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", `Token token="`+s.authToken+`"`)

	s.response, err = s.tc.HTTPClient.Do(req)
	if err != nil {
		return err
	}

	s.responseBody, err = io.ReadAll(s.response.Body)
	_ = s.response.Body.Close()
	return err
}

func (s *StepsContext) theVariableHasValue(variableId, value string) error {
	resourceId := s.account + ":variable:" + variableId
	encryptedValue, err := s.tc.Cipher.Encrypt([]byte(resourceId), []byte(value))
	if err != nil {
		return err
	}

	return s.tc.DB.Exec(`
		INSERT INTO secrets (resource_id, value) VALUES (?, ?)
	`, resourceId, encryptedValue).Error
}

func (s *StepsContext) iBatchRetrieveVariables(variableIds string) error {
	url := fmt.Sprintf("%s/secrets?variable_ids=%s", s.tc.ServerURL, variableIds)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", `Token token="`+s.authToken+`"`)

	s.response, err = s.tc.HTTPClient.Do(req)
	if err != nil {
		return err
	}

	s.responseBody, err = io.ReadAll(s.response.Body)
	_ = s.response.Body.Close()
	return err
}

func (s *StepsContext) theResponseShouldContainSecret(resourceId, expectedValue string) error {
	var secrets map[string]string
	if err := json.Unmarshal(s.responseBody, &secrets); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	actualValue, ok := secrets[resourceId]
	if !ok {
		return fmt.Errorf("secret %s not found in response", resourceId)
	}
	if actualValue != expectedValue {
		return fmt.Errorf("expected secret value %q, got %q", expectedValue, actualValue)
	}
	return nil
}

// Policy steps

func (s *StepsContext) iLoadPolicyTo(policyId string, policyYAML *godog.DocString) error {
	url := fmt.Sprintf("%s/policies/%s/policy/%s", s.tc.ServerURL, s.account, policyId)
	req, err := http.NewRequest("POST", url, bytes.NewReader([]byte(policyYAML.Content)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", `Token token="`+s.authToken+`"`)
	req.Header.Set("Content-Type", "application/x-yaml")

	s.response, err = s.tc.HTTPClient.Do(req)
	if err != nil {
		return err
	}

	s.responseBody, err = io.ReadAll(s.response.Body)
	_ = s.response.Body.Close()
	return err
}

func (s *StepsContext) iValidatePolicyFor(policyId string, policyYAML *godog.DocString) error {
	url := fmt.Sprintf("%s/policies/%s/policy/%s?dry_run=true", s.tc.ServerURL, s.account, policyId)
	req, err := http.NewRequest("POST", url, bytes.NewReader([]byte(policyYAML.Content)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", `Token token="`+s.authToken+`"`)
	req.Header.Set("Content-Type", "application/x-yaml")

	s.response, err = s.tc.HTTPClient.Do(req)
	if err != nil {
		return err
	}

	s.responseBody, err = io.ReadAll(s.response.Body)
	_ = s.response.Body.Close()
	return err
}

func (s *StepsContext) thePolicyVersionShouldBeGreaterThan(minVersion int) error {
	var result map[string]interface{}
	if err := json.Unmarshal(s.responseBody, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	version, ok := result["version"].(float64)
	if !ok {
		return fmt.Errorf("version not found in response")
	}

	if int(version) <= minVersion {
		return fmt.Errorf("expected version > %d, got %d", minVersion, int(version))
	}
	return nil
}

func (s *StepsContext) userShouldExistInAccount(userId, account string) error {
	roleId := account + ":user:" + userId
	var count int64
	if err := s.tc.DB.Raw(`SELECT COUNT(*) FROM roles WHERE role_id = ?`, roleId).Scan(&count).Error; err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("user %s does not exist", roleId)
	}
	return nil
}

func (s *StepsContext) userShouldNotExistInAccount(userId, account string) error {
	roleId := account + ":user:" + userId
	var count int64
	if err := s.tc.DB.Raw(`SELECT COUNT(*) FROM roles WHERE role_id = ?`, roleId).Scan(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("user %s should not exist but does", roleId)
	}
	return nil
}

func (s *StepsContext) groupShouldExistInAccount(groupId, account string) error {
	roleId := account + ":group:" + groupId
	var count int64
	if err := s.tc.DB.Raw(`SELECT COUNT(*) FROM roles WHERE role_id = ?`, roleId).Scan(&count).Error; err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("group %s does not exist", roleId)
	}
	return nil
}

func (s *StepsContext) variableShouldExistInAccount(variableId, account string) error {
	resourceId := account + ":variable:" + variableId
	var count int64
	if err := s.tc.DB.Raw(`SELECT COUNT(*) FROM resources WHERE resource_id = ?`, resourceId).Scan(&count).Error; err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("variable %s does not exist", resourceId)
	}
	return nil
}

func (s *StepsContext) theResponseShouldIndicateDryRunMode() error {
	var result map[string]interface{}
	if err := json.Unmarshal(s.responseBody, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	dryRun, ok := result["dry_run"].(bool)
	if !ok || !dryRun {
		return fmt.Errorf("expected dry_run=true in response")
	}
	return nil
}
