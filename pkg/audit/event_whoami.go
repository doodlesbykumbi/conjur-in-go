package audit

import "fmt"

// WhoamiEvent represents a whoami audit event
type WhoamiEvent struct {
	RoleID   string
	ClientIP string
	Success  bool
}

func (e WhoamiEvent) MessageID() string {
	return "identity-check"
}

func (e WhoamiEvent) Message() string {
	return fmt.Sprintf("%s checked its identity using whoami", e.RoleID)
}

func (e WhoamiEvent) Severity() Severity {
	if e.Success {
		return SeverityInfo
	}
	return SeverityWarning
}

func (e WhoamiEvent) Facility() int {
	return FacilityAuth
}

func (e WhoamiEvent) StructuredData() map[string]map[string]string {
	result := "success"
	if !e.Success {
		result = "failure"
	}
	return map[string]map[string]string{
		SDIDSubject: {
			"role": e.RoleID,
		},
		SDIDAuth: {
			"user": e.RoleID,
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
