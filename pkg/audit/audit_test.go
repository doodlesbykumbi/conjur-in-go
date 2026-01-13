package audit

import (
	"bytes"
	"strings"
	"testing"
)

func TestLoggerFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger()
	logger.SetWriter(&buf)

	event := AuthenticateEvent{
		RoleID:            "myorg:user:admin",
		ClientIP:          "192.168.1.1",
		AuthenticatorName: "authn",
		Success:           true,
	}

	logger.Log(event)

	output := buf.String()

	// Check RFC5424 format components
	if !strings.Contains(output, "conjur") {
		t.Error("Expected app name 'conjur' in output")
	}
	if !strings.Contains(output, "authn") {
		t.Error("Expected message ID 'authn' in output")
	}
	if !strings.Contains(output, "myorg:user:admin") {
		t.Error("Expected role ID in output")
	}
	if !strings.Contains(output, "192.168.1.1") {
		t.Error("Expected client IP in output")
	}
	if !strings.Contains(output, "successfully authenticated") {
		t.Error("Expected success message in output")
	}
}

func TestAuthenticateEvent(t *testing.T) {
	tests := []struct {
		name      string
		event     AuthenticateEvent
		wantMsg   string
		wantSev   Severity
		wantFac   int
		wantMsgID string
	}{
		{
			name: "successful authentication",
			event: AuthenticateEvent{
				RoleID:            "myorg:user:admin",
				ClientIP:          "10.0.0.1",
				AuthenticatorName: "authn",
				Success:           true,
			},
			wantMsg:   "successfully authenticated",
			wantSev:   SeverityInfo,
			wantFac:   FacilityAuthPriv,
			wantMsgID: "authn",
		},
		{
			name: "failed authentication",
			event: AuthenticateEvent{
				RoleID:            "myorg:user:admin",
				ClientIP:          "10.0.0.1",
				AuthenticatorName: "authn",
				Success:           false,
				ErrorMessage:      "invalid credentials",
			},
			wantMsg:   "failed to authenticate",
			wantSev:   SeverityWarning,
			wantFac:   FacilityAuthPriv,
			wantMsgID: "authn",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.event.Message(), tt.wantMsg) {
				t.Errorf("Message() = %q, want to contain %q", tt.event.Message(), tt.wantMsg)
			}
			if tt.event.Severity() != tt.wantSev {
				t.Errorf("Severity() = %v, want %v", tt.event.Severity(), tt.wantSev)
			}
			if tt.event.Facility() != tt.wantFac {
				t.Errorf("Facility() = %v, want %v", tt.event.Facility(), tt.wantFac)
			}
			if tt.event.MessageID() != tt.wantMsgID {
				t.Errorf("MessageID() = %v, want %v", tt.event.MessageID(), tt.wantMsgID)
			}
		})
	}
}

func TestFetchEvent(t *testing.T) {
	tests := []struct {
		name    string
		event   FetchEvent
		wantMsg string
		wantSev Severity
	}{
		{
			name: "successful fetch",
			event: FetchEvent{
				UserID:     "myorg:user:admin",
				ClientIP:   "10.0.0.1",
				ResourceID: "myorg:variable:db/password",
				Success:    true,
			},
			wantMsg: "fetched",
			wantSev: SeverityInfo,
		},
		{
			name: "fetch with version",
			event: FetchEvent{
				UserID:     "myorg:user:admin",
				ClientIP:   "10.0.0.1",
				ResourceID: "myorg:variable:db/password",
				Version:    "3",
				Success:    true,
			},
			wantMsg: "version 3",
			wantSev: SeverityInfo,
		},
		{
			name: "failed fetch",
			event: FetchEvent{
				UserID:       "myorg:user:admin",
				ClientIP:     "10.0.0.1",
				ResourceID:   "myorg:variable:db/password",
				Success:      false,
				ErrorMessage: "not found",
			},
			wantMsg: "tried to fetch",
			wantSev: SeverityWarning,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.event.Message(), tt.wantMsg) {
				t.Errorf("Message() = %q, want to contain %q", tt.event.Message(), tt.wantMsg)
			}
			if tt.event.Severity() != tt.wantSev {
				t.Errorf("Severity() = %v, want %v", tt.event.Severity(), tt.wantSev)
			}
			if tt.event.MessageID() != "fetch" {
				t.Errorf("MessageID() = %v, want 'fetch'", tt.event.MessageID())
			}
		})
	}
}

func TestUpdateEvent(t *testing.T) {
	event := UpdateEvent{
		UserID:     "myorg:user:admin",
		ClientIP:   "10.0.0.1",
		ResourceID: "myorg:variable:db/password",
		Success:    true,
	}

	if event.MessageID() != "update" {
		t.Errorf("MessageID() = %v, want 'update'", event.MessageID())
	}
	if !strings.Contains(event.Message(), "updated") {
		t.Errorf("Message() = %q, want to contain 'updated'", event.Message())
	}
	if event.Severity() != SeverityInfo {
		t.Errorf("Severity() = %v, want SeverityInfo", event.Severity())
	}
}

func TestPolicyEvent(t *testing.T) {
	event := PolicyEvent{
		UserID:        "myorg:user:admin",
		ClientIP:      "10.0.0.1",
		ResourceID:    "myorg:policy:root",
		PolicyVersion: 5,
		Operation:     "update",
		Success:       true,
	}

	if event.MessageID() != "policy" {
		t.Errorf("MessageID() = %v, want 'policy'", event.MessageID())
	}
	if !strings.Contains(event.Message(), "version 5") {
		t.Errorf("Message() = %q, want to contain 'version 5'", event.Message())
	}
	if !strings.Contains(event.Message(), "updated") {
		t.Errorf("Message() = %q, want to contain 'updated'", event.Message())
	}
}

func TestCheckEvent(t *testing.T) {
	tests := []struct {
		name    string
		event   CheckEvent
		wantMsg string
	}{
		{
			name: "allowed",
			event: CheckEvent{
				UserID:     "myorg:user:admin",
				ClientIP:   "10.0.0.1",
				ResourceID: "myorg:variable:db/password",
				Privilege:  "execute",
				Allowed:    true,
			},
			wantMsg: "allowed",
		},
		{
			name: "denied",
			event: CheckEvent{
				UserID:     "myorg:user:guest",
				ClientIP:   "10.0.0.1",
				ResourceID: "myorg:variable:db/password",
				Privilege:  "execute",
				Allowed:    false,
			},
			wantMsg: "denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.event.Message(), tt.wantMsg) {
				t.Errorf("Message() = %q, want to contain %q", tt.event.Message(), tt.wantMsg)
			}
			if tt.event.MessageID() != "check" {
				t.Errorf("MessageID() = %v, want 'check'", tt.event.MessageID())
			}
		})
	}
}

func TestAPIKeyRotationEvent(t *testing.T) {
	tests := []struct {
		name    string
		event   APIKeyRotationEvent
		wantMsg string
	}{
		{
			name: "self rotation",
			event: APIKeyRotationEvent{
				AuthenticatedRoleID: "myorg:user:admin",
				RotatedRoleID:       "myorg:user:admin",
				ClientIP:            "10.0.0.1",
				Success:             true,
			},
			wantMsg: "rotated their own API key",
		},
		{
			name: "rotate other",
			event: APIKeyRotationEvent{
				AuthenticatedRoleID: "myorg:user:admin",
				RotatedRoleID:       "myorg:user:guest",
				ClientIP:            "10.0.0.1",
				Success:             true,
			},
			wantMsg: "rotated API key for",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.event.Message(), tt.wantMsg) {
				t.Errorf("Message() = %q, want to contain %q", tt.event.Message(), tt.wantMsg)
			}
			if tt.event.MessageID() != "api-key" {
				t.Errorf("MessageID() = %v, want 'api-key'", tt.event.MessageID())
			}
		})
	}
}

func TestListEvent(t *testing.T) {
	event := ListEvent{
		UserID:   "myorg:user:admin",
		ClientIP: "10.0.0.1",
		Account:  "myorg",
		Kind:     "variable",
		Search:   "db",
		Success:  true,
	}

	if event.MessageID() != "list" {
		t.Errorf("MessageID() = %v, want 'list'", event.MessageID())
	}
	if !strings.Contains(event.Message(), "listed resources") {
		t.Errorf("Message() = %q, want to contain 'listed resources'", event.Message())
	}
	if !strings.Contains(event.Message(), "kind=variable") {
		t.Errorf("Message() = %q, want to contain 'kind=variable'", event.Message())
	}
}

func TestShowEvent(t *testing.T) {
	event := ShowEvent{
		UserID:       "myorg:user:admin",
		ClientIP:     "10.0.0.1",
		ResourceID:   "myorg:variable:db/password",
		ResourceKind: "resource",
		Success:      true,
	}

	if event.MessageID() != "resource" {
		t.Errorf("MessageID() = %v, want 'resource'", event.MessageID())
	}
	if !strings.Contains(event.Message(), "fetched resource details") {
		t.Errorf("Message() = %q, want to contain 'fetched resource details'", event.Message())
	}
}

func TestWhoamiEvent(t *testing.T) {
	event := WhoamiEvent{
		RoleID:   "myorg:user:admin",
		ClientIP: "10.0.0.1",
		Success:  true,
	}

	if event.MessageID() != "identity-check" {
		t.Errorf("MessageID() = %v, want 'identity-check'", event.MessageID())
	}
	if !strings.Contains(event.Message(), "checked its identity") {
		t.Errorf("Message() = %q, want to contain 'checked its identity'", event.Message())
	}
	if event.Facility() != FacilityAuth {
		t.Errorf("Facility() = %v, want FacilityAuth", event.Facility())
	}
}

func TestPasswordEvent(t *testing.T) {
	event := PasswordEvent{
		UserID:   "myorg:user:admin",
		ClientIP: "10.0.0.1",
		Success:  true,
	}

	if event.MessageID() != "password" {
		t.Errorf("MessageID() = %v, want 'password'", event.MessageID())
	}
	if !strings.Contains(event.Message(), "changed their password") {
		t.Errorf("Message() = %q, want to contain 'changed their password'", event.Message())
	}
}

func TestMembersEvent(t *testing.T) {
	event := MembersEvent{
		UserID:   "myorg:user:admin",
		ClientIP: "10.0.0.1",
		RoleID:   "myorg:group:admins",
		Success:  true,
	}

	if event.MessageID() != "members" {
		t.Errorf("MessageID() = %v, want 'members'", event.MessageID())
	}
	if !strings.Contains(event.Message(), "listed members of") {
		t.Errorf("Message() = %q, want to contain 'listed members of'", event.Message())
	}
}

func TestMembershipsEvent(t *testing.T) {
	event := MembershipsEvent{
		UserID:   "myorg:user:admin",
		ClientIP: "10.0.0.1",
		RoleID:   "myorg:user:guest",
		Success:  true,
	}

	if event.MessageID() != "memberships" {
		t.Errorf("MessageID() = %v, want 'memberships'", event.MessageID())
	}
	if !strings.Contains(event.Message(), "listed memberships of") {
		t.Errorf("Message() = %q, want to contain 'listed memberships of'", event.Message())
	}
}

func TestHostFactoryEvent(t *testing.T) {
	tests := []struct {
		name    string
		event   HostFactoryEvent
		wantMsg string
	}{
		{
			name: "create token",
			event: HostFactoryEvent{
				UserID:        "myorg:user:admin",
				ClientIP:      "10.0.0.1",
				HostFactoryID: "myorg:host_factory:servers",
				Operation:     "create-token",
				Success:       true,
			},
			wantMsg: "created token for",
		},
		{
			name: "revoke token",
			event: HostFactoryEvent{
				UserID:        "myorg:user:admin",
				ClientIP:      "10.0.0.1",
				HostFactoryID: "myorg:host_factory:servers",
				Operation:     "revoke-token",
				Success:       true,
			},
			wantMsg: "revoked token for",
		},
		{
			name: "create host",
			event: HostFactoryEvent{
				UserID:        "myorg:user:admin",
				ClientIP:      "10.0.0.1",
				HostFactoryID: "myorg:host_factory:servers",
				Operation:     "create-host",
				HostID:        "myorg:host:server-01",
				Success:       true,
			},
			wantMsg: "created host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.event.Message(), tt.wantMsg) {
				t.Errorf("Message() = %q, want to contain %q", tt.event.Message(), tt.wantMsg)
			}
			if tt.event.MessageID() != "host-factory" {
				t.Errorf("MessageID() = %v, want 'host-factory'", tt.event.MessageID())
			}
		})
	}
}

func TestStructuredData(t *testing.T) {
	event := FetchEvent{
		UserID:     "myorg:user:admin",
		ClientIP:   "10.0.0.1",
		ResourceID: "myorg:variable:db/password",
		Success:    true,
	}

	sd := event.StructuredData()

	if sd[SDIDAuth]["user"] != "myorg:user:admin" {
		t.Errorf("StructuredData auth.user = %v, want 'myorg:user:admin'", sd[SDIDAuth]["user"])
	}
	if sd[SDIDSubject]["resource"] != "myorg:variable:db/password" {
		t.Errorf("StructuredData subject.resource = %v, want 'myorg:variable:db/password'", sd[SDIDSubject]["resource"])
	}
	if sd[SDIDClient]["ip"] != "10.0.0.1" {
		t.Errorf("StructuredData client.ip = %v, want '10.0.0.1'", sd[SDIDClient]["ip"])
	}
	if sd[SDIDAction]["result"] != "success" {
		t.Errorf("StructuredData action.result = %v, want 'success'", sd[SDIDAction]["result"])
	}
}

func TestAuditToggle(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger()
	logger.SetWriter(&buf)

	// Save original state
	originalEnabled := auditEnabled
	defer func() {
		auditEnabled = originalEnabled
	}()

	// Test with audit disabled
	SetEnabled(false)
	if IsEnabled() {
		t.Error("Expected audit to be disabled")
	}

	// Test with audit enabled
	SetEnabled(true)
	if !IsEnabled() {
		t.Error("Expected audit to be enabled")
	}
}

func TestEscapeSDValue(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple", `"simple"`},
		{`with"quote`, `"with\"quote"`},
		{`with\backslash`, `"with\\backslash"`},
		{`with]bracket`, `"with\]bracket"`},
		{`all"special\chars]`, `"all\"special\\chars\]"`},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := escapeSDValue(tt.input)
			if got != tt.want {
				t.Errorf("escapeSDValue(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
