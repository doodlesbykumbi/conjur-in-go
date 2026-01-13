package audit

import "fmt"

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
