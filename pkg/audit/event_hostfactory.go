package audit

import "fmt"

// HostFactoryEvent represents a host factory operation audit event
type HostFactoryEvent struct {
	UserID        string
	ClientIP      string
	HostFactoryID string
	Operation     string // "create-token", "revoke-token", "create-host"
	HostID        string // for create-host
	Success       bool
	ErrorMessage  string
}

func (e HostFactoryEvent) MessageID() string {
	return "host-factory"
}

func (e HostFactoryEvent) Message() string {
	var action string
	switch e.Operation {
	case "create-token":
		action = "created token for"
	case "revoke-token":
		action = "revoked token for"
	case "create-host":
		if e.Success {
			return fmt.Sprintf("%s created host %s via %s", e.UserID, e.HostID, e.HostFactoryID)
		}
		return fmt.Sprintf("%s failed to create host via %s", e.UserID, e.HostFactoryID)
	default:
		action = e.Operation
	}
	if e.Success {
		return fmt.Sprintf("%s %s %s", e.UserID, action, e.HostFactoryID)
	}
	msg := fmt.Sprintf("%s failed to %s %s", e.UserID, e.Operation, e.HostFactoryID)
	if e.ErrorMessage != "" {
		msg += ": " + e.ErrorMessage
	}
	return msg
}

func (e HostFactoryEvent) Severity() Severity {
	if e.Success {
		return SeverityInfo
	}
	return SeverityWarning
}

func (e HostFactoryEvent) Facility() int {
	return FacilityAuthPriv
}

func (e HostFactoryEvent) StructuredData() map[string]map[string]string {
	result := "success"
	if !e.Success {
		result = "failure"
	}
	subject := map[string]string{
		"resource": e.HostFactoryID,
	}
	if e.HostID != "" {
		subject["host"] = e.HostID
	}
	return map[string]map[string]string{
		SDIDAuth: {
			"user": e.UserID,
		},
		SDIDSubject: subject,
		SDIDClient: {
			"ip": e.ClientIP,
		},
		SDIDAction: {
			"operation": e.Operation,
			"result":    result,
		},
	}
}
