package audit

import "fmt"

// ListEvent represents a resource list audit event
type ListEvent struct {
	UserID       string
	ClientIP     string
	Account      string
	Kind         string
	Search       string
	Limit        int
	Offset       int
	Success      bool
	ErrorMessage string
}

func (e ListEvent) MessageID() string {
	return "list"
}

func (e ListEvent) Message() string {
	params := fmt.Sprintf("account=%s", e.Account)
	if e.Kind != "" {
		params += fmt.Sprintf(", kind=%s", e.Kind)
	}
	if e.Search != "" {
		params += fmt.Sprintf(", search=%s", e.Search)
	}
	if e.Success {
		return fmt.Sprintf("%s successfully listed resources with parameters: %s", e.UserID, params)
	}
	msg := fmt.Sprintf("%s failed to list resources with parameters: %s", e.UserID, params)
	if e.ErrorMessage != "" {
		msg += ": " + e.ErrorMessage
	}
	return msg
}

func (e ListEvent) Severity() Severity {
	if e.Success {
		return SeverityInfo
	}
	return SeverityWarning
}

func (e ListEvent) Facility() int {
	return FacilityAuthPriv
}

func (e ListEvent) StructuredData() map[string]map[string]string {
	result := "success"
	if !e.Success {
		result = "failure"
	}
	subject := map[string]string{
		"account": e.Account,
	}
	if e.Kind != "" {
		subject["kind"] = e.Kind
	}
	if e.Search != "" {
		subject["search"] = e.Search
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
			"operation": "list",
			"result":    result,
		},
	}
}
