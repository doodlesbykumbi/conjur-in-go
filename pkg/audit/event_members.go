package audit

import "fmt"

// MembersEvent represents a role members list audit event
type MembersEvent struct {
	UserID       string
	ClientIP     string
	RoleID       string
	Success      bool
	ErrorMessage string
}

func (e MembersEvent) MessageID() string {
	return "members"
}

func (e MembersEvent) Message() string {
	if e.Success {
		return fmt.Sprintf("%s listed members of %s", e.UserID, e.RoleID)
	}
	msg := fmt.Sprintf("%s failed to list members of %s", e.UserID, e.RoleID)
	if e.ErrorMessage != "" {
		msg += ": " + e.ErrorMessage
	}
	return msg
}

func (e MembersEvent) Severity() Severity {
	if e.Success {
		return SeverityInfo
	}
	return SeverityWarning
}

func (e MembersEvent) Facility() int {
	return FacilityAuthPriv
}

func (e MembersEvent) StructuredData() map[string]map[string]string {
	result := "success"
	if !e.Success {
		result = "failure"
	}
	return map[string]map[string]string{
		SDIDAuth: {
			"user": e.UserID,
		},
		SDIDSubject: {
			"role": e.RoleID,
		},
		SDIDClient: {
			"ip": e.ClientIP,
		},
		SDIDAction: {
			"operation": "list-members",
			"result":    result,
		},
	}
}

// MembershipsEvent represents a role memberships list audit event
type MembershipsEvent struct {
	UserID       string
	ClientIP     string
	RoleID       string
	Success      bool
	ErrorMessage string
}

func (e MembershipsEvent) MessageID() string {
	return "memberships"
}

func (e MembershipsEvent) Message() string {
	if e.Success {
		return fmt.Sprintf("%s listed memberships of %s", e.UserID, e.RoleID)
	}
	msg := fmt.Sprintf("%s failed to list memberships of %s", e.UserID, e.RoleID)
	if e.ErrorMessage != "" {
		msg += ": " + e.ErrorMessage
	}
	return msg
}

func (e MembershipsEvent) Severity() Severity {
	if e.Success {
		return SeverityInfo
	}
	return SeverityWarning
}

func (e MembershipsEvent) Facility() int {
	return FacilityAuthPriv
}

func (e MembershipsEvent) StructuredData() map[string]map[string]string {
	result := "success"
	if !e.Success {
		result = "failure"
	}
	return map[string]map[string]string{
		SDIDAuth: {
			"user": e.UserID,
		},
		SDIDSubject: {
			"role": e.RoleID,
		},
		SDIDClient: {
			"ip": e.ClientIP,
		},
		SDIDAction: {
			"operation": "list-memberships",
			"result":    result,
		},
	}
}
