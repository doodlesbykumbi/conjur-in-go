package audit

import "fmt"

// ShowEvent represents a resource/role show audit event
type ShowEvent struct {
	UserID       string
	ClientIP     string
	ResourceID   string
	ResourceKind string // "resource", "role"
	Success      bool
	ErrorMessage string
}

func (e ShowEvent) MessageID() string {
	return e.ResourceKind
}

func (e ShowEvent) Message() string {
	if e.Success {
		return fmt.Sprintf("%s successfully fetched %s details", e.UserID, e.ResourceKind)
	}
	msg := fmt.Sprintf("%s failed to fetch %s details", e.UserID, e.ResourceKind)
	if e.ErrorMessage != "" {
		msg += ": " + e.ErrorMessage
	}
	return msg
}

func (e ShowEvent) Severity() Severity {
	if e.Success {
		return SeverityInfo
	}
	return SeverityWarning
}

func (e ShowEvent) Facility() int {
	return FacilityAuthPriv
}

func (e ShowEvent) StructuredData() map[string]map[string]string {
	result := "success"
	if !e.Success {
		result = "failure"
	}
	subjectKey := "resource"
	if e.ResourceKind == "role" {
		subjectKey = "role"
	}
	return map[string]map[string]string{
		SDIDAuth: {
			"user": e.UserID,
		},
		SDIDSubject: {
			subjectKey: e.ResourceID,
		},
		SDIDClient: {
			"ip": e.ClientIP,
		},
		SDIDAction: {
			"operation": "get",
			"result":    result,
		},
	}
}
