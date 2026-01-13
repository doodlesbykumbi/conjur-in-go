package audit

import "fmt"

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
