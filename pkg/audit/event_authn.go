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
