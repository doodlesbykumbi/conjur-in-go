package audit

import "fmt"

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
