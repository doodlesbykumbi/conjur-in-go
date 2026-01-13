package audit

import "fmt"

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
	var verb string
	switch e.Operation {
	case "add":
		verb = "added"
	case "update":
		verb = "updated"
	case "replace":
		verb = "replaced"
	default:
		verb = e.Operation + "d"
	}
	if e.Success {
		return fmt.Sprintf("%s %s policy %s (version %d)", e.UserID, verb, e.ResourceID, e.PolicyVersion)
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
