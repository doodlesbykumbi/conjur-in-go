package audit

import "fmt"

// AuthenticateEvent represents an authentication audit event
type AuthenticateEvent struct {
	RoleID            string
	ClientIP          string
	AuthenticatorName string
	ServiceID         string
	Success           bool
	ErrorMessage      string
}

func (e AuthenticateEvent) MessageID() string {
	return "authn"
}

func (e AuthenticateEvent) Message() string {
	if e.Success {
		return fmt.Sprintf("%s successfully authenticated with authenticator %s", e.RoleID, e.AuthenticatorName)
	}
	msg := fmt.Sprintf("%s failed to authenticate with authenticator %s", e.RoleID, e.AuthenticatorName)
	if e.ErrorMessage != "" {
		msg += ": " + e.ErrorMessage
	}
	return msg
}

func (e AuthenticateEvent) Severity() Severity {
	if e.Success {
		return SeverityInfo
	}
	return SeverityWarning
}

func (e AuthenticateEvent) Facility() int {
	return FacilityAuthPriv
}

func (e AuthenticateEvent) StructuredData() map[string]map[string]string {
	sd := map[string]map[string]string{
		SDIDAuth: {
			"authenticator": e.AuthenticatorName,
			"user":          e.RoleID,
		},
		SDIDClient: {
			"ip": e.ClientIP,
		},
	}
	if e.ServiceID != "" {
		sd[SDIDAuth]["service"] = e.ServiceID
	}
	return sd
}

// FetchEvent represents a secret fetch audit event
type FetchEvent struct {
	UserID       string
	ClientIP     string
	ResourceID   string
	Version      string
	Success      bool
	ErrorMessage string
}

func (e FetchEvent) MessageID() string {
	return "fetch"
}

func (e FetchEvent) Message() string {
	resource := e.ResourceID
	if e.Version != "" {
		resource = fmt.Sprintf("version %s of %s", e.Version, e.ResourceID)
	}
	if e.Success {
		return fmt.Sprintf("%s fetched %s", e.UserID, resource)
	}
	msg := fmt.Sprintf("%s tried to fetch %s", e.UserID, resource)
	if e.ErrorMessage != "" {
		msg += ": " + e.ErrorMessage
	}
	return msg
}

func (e FetchEvent) Severity() Severity {
	if e.Success {
		return SeverityInfo
	}
	return SeverityWarning
}

func (e FetchEvent) Facility() int {
	return FacilityAuthPriv
}

func (e FetchEvent) StructuredData() map[string]map[string]string {
	sd := map[string]map[string]string{
		SDIDAuth: {
			"user": e.UserID,
		},
		SDIDSubject: {
			"resource": e.ResourceID,
		},
		SDIDClient: {
			"ip": e.ClientIP,
		},
		SDIDAction: {
			"operation": "fetch",
		},
	}
	if e.Version != "" {
		sd[SDIDSubject]["version"] = e.Version
	}
	if e.Success {
		sd[SDIDAction]["result"] = "success"
	} else {
		sd[SDIDAction]["result"] = "failure"
	}
	return sd
}

// UpdateEvent represents a secret update audit event
type UpdateEvent struct {
	UserID       string
	ClientIP     string
	ResourceID   string
	Success      bool
	ErrorMessage string
}

func (e UpdateEvent) MessageID() string {
	return "update"
}

func (e UpdateEvent) Message() string {
	if e.Success {
		return fmt.Sprintf("%s updated %s", e.UserID, e.ResourceID)
	}
	msg := fmt.Sprintf("%s tried to update %s", e.UserID, e.ResourceID)
	if e.ErrorMessage != "" {
		msg += ": " + e.ErrorMessage
	}
	return msg
}

func (e UpdateEvent) Severity() Severity {
	if e.Success {
		return SeverityInfo
	}
	return SeverityWarning
}

func (e UpdateEvent) Facility() int {
	return FacilityAuthPriv
}

func (e UpdateEvent) StructuredData() map[string]map[string]string {
	sd := map[string]map[string]string{
		SDIDAuth: {
			"user": e.UserID,
		},
		SDIDSubject: {
			"resource": e.ResourceID,
		},
		SDIDClient: {
			"ip": e.ClientIP,
		},
		SDIDAction: {
			"operation": "update",
		},
	}
	if e.Success {
		sd[SDIDAction]["result"] = "success"
	} else {
		sd[SDIDAction]["result"] = "failure"
	}
	return sd
}

// PolicyEvent represents a policy load audit event
type PolicyEvent struct {
	UserID        string
	ClientIP      string
	ResourceID    string
	PolicyVersion int
	Operation     string // "add", "update", "replace"
	Success       bool
	ErrorMessage  string
}

func (e PolicyEvent) MessageID() string {
	return "policy"
}

func (e PolicyEvent) Message() string {
	if e.Success {
		return fmt.Sprintf("%s %sed policy %s (version %d)", e.UserID, e.Operation, e.ResourceID, e.PolicyVersion)
	}
	msg := fmt.Sprintf("%s tried to %s policy %s", e.UserID, e.Operation, e.ResourceID)
	if e.ErrorMessage != "" {
		msg += ": " + e.ErrorMessage
	}
	return msg
}

func (e PolicyEvent) Severity() Severity {
	if e.Success {
		return SeverityInfo
	}
	return SeverityWarning
}

func (e PolicyEvent) Facility() int {
	return FacilityAuthPriv
}

func (e PolicyEvent) StructuredData() map[string]map[string]string {
	sd := map[string]map[string]string{
		SDIDAuth: {
			"user": e.UserID,
		},
		SDIDPolicy: {
			"id":      e.ResourceID,
			"version": fmt.Sprintf("%d", e.PolicyVersion),
		},
		SDIDClient: {
			"ip": e.ClientIP,
		},
		SDIDAction: {
			"operation": e.Operation,
		},
	}
	if e.Success {
		sd[SDIDAction]["result"] = "success"
	} else {
		sd[SDIDAction]["result"] = "failure"
	}
	return sd
}

// CheckEvent represents a permission check audit event
type CheckEvent struct {
	UserID       string
	ClientIP     string
	ResourceID   string
	Privilege    string
	Allowed      bool
	ErrorMessage string
}

func (e CheckEvent) MessageID() string {
	return "check"
}

func (e CheckEvent) Message() string {
	if e.Allowed {
		return fmt.Sprintf("%s checked permission %s on %s: allowed", e.UserID, e.Privilege, e.ResourceID)
	}
	return fmt.Sprintf("%s checked permission %s on %s: denied", e.UserID, e.Privilege, e.ResourceID)
}

func (e CheckEvent) Severity() Severity {
	return SeverityInfo
}

func (e CheckEvent) Facility() int {
	return FacilityAuthPriv
}

func (e CheckEvent) StructuredData() map[string]map[string]string {
	result := "success"
	if !e.Allowed {
		result = "failure"
	}
	return map[string]map[string]string{
		SDIDAuth: {
			"user": e.UserID,
		},
		SDIDSubject: {
			"resource":  e.ResourceID,
			"privilege": e.Privilege,
		},
		SDIDClient: {
			"ip": e.ClientIP,
		},
		SDIDAction: {
			"operation": "check",
			"result":    result,
		},
	}
}

// APIKeyRotationEvent represents an API key rotation audit event
type APIKeyRotationEvent struct {
	AuthenticatedRoleID string
	RotatedRoleID       string
	ClientIP            string
	Success             bool
	ErrorMessage        string
}

func (e APIKeyRotationEvent) MessageID() string {
	return "api-key"
}

func (e APIKeyRotationEvent) Message() string {
	if e.AuthenticatedRoleID == e.RotatedRoleID {
		if e.Success {
			return fmt.Sprintf("%s rotated their own API key", e.AuthenticatedRoleID)
		}
		msg := fmt.Sprintf("%s failed to rotate their own API key", e.AuthenticatedRoleID)
		if e.ErrorMessage != "" {
			msg += ": " + e.ErrorMessage
		}
		return msg
	}
	if e.Success {
		return fmt.Sprintf("%s rotated API key for %s", e.AuthenticatedRoleID, e.RotatedRoleID)
	}
	msg := fmt.Sprintf("%s failed to rotate API key for %s", e.AuthenticatedRoleID, e.RotatedRoleID)
	if e.ErrorMessage != "" {
		msg += ": " + e.ErrorMessage
	}
	return msg
}

func (e APIKeyRotationEvent) Severity() Severity {
	if e.Success {
		return SeverityInfo
	}
	return SeverityWarning
}

func (e APIKeyRotationEvent) Facility() int {
	return FacilityAuthPriv
}

func (e APIKeyRotationEvent) StructuredData() map[string]map[string]string {
	result := "success"
	if !e.Success {
		result = "failure"
	}
	return map[string]map[string]string{
		SDIDAuth: {
			"user": e.AuthenticatedRoleID,
		},
		SDIDSubject: {
			"role": e.RotatedRoleID,
		},
		SDIDClient: {
			"ip": e.ClientIP,
		},
		SDIDAction: {
			"operation": "rotate-api-key",
			"result":    result,
		},
	}
}
