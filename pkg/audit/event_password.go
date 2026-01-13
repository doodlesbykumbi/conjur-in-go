package audit

import "fmt"

// PasswordEvent represents a password change audit event
type PasswordEvent struct {
	UserID       string
	ClientIP     string
	Success      bool
	ErrorMessage string
}

func (e PasswordEvent) MessageID() string {
	return "password"
}

func (e PasswordEvent) Message() string {
	if e.Success {
		return fmt.Sprintf("%s successfully changed their password", e.UserID)
	}
	msg := fmt.Sprintf("%s failed to change their password", e.UserID)
	if e.ErrorMessage != "" {
		msg += ": " + e.ErrorMessage
	}
	return msg
}

func (e PasswordEvent) Severity() Severity {
	if e.Success {
		return SeverityInfo
	}
	return SeverityWarning
}

func (e PasswordEvent) Facility() int {
	return FacilityAuthPriv
}

func (e PasswordEvent) StructuredData() map[string]map[string]string {
	result := "success"
	if !e.Success {
		result = "failure"
	}
	return map[string]map[string]string{
		SDIDAuth: {
			"user": e.UserID,
		},
		SDIDSubject: {
			"role": e.UserID,
		},
		SDIDClient: {
			"ip": e.ClientIP,
		},
		SDIDAction: {
			"operation": "change-password",
			"result":    result,
		},
	}
}
