package audit

import "fmt"

// FetchEvent represents a secret fetch audit event
type FetchEvent struct {
	UserID       string
	ClientIP     string
	ResourceID   string
	Version      string
	Success      bool
	ErrorMessage string
}

func (e FetchEvent) MessageID() string {
	return "fetch"
}

func (e FetchEvent) Message() string {
	resource := e.ResourceID
	if e.Version != "" {
		resource = fmt.Sprintf("version %s of %s", e.Version, e.ResourceID)
	}
	if e.Success {
		return fmt.Sprintf("%s fetched %s", e.UserID, resource)
	}
	msg := fmt.Sprintf("%s tried to fetch %s", e.UserID, resource)
	if e.ErrorMessage != "" {
		msg += ": " + e.ErrorMessage
	}
	return msg
}

func (e FetchEvent) Severity() Severity {
	if e.Success {
		return SeverityInfo
	}
	return SeverityWarning
}

func (e FetchEvent) Facility() int {
	return FacilityAuthPriv
}

func (e FetchEvent) StructuredData() map[string]map[string]string {
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
			"operation": "fetch",
		},
	}
	if e.Version != "" {
		sd[SDIDSubject]["version"] = e.Version
	}
	if e.Success {
		sd[SDIDAction]["result"] = "success"
	} else {
		sd[SDIDAction]["result"] = "failure"
	}
	return sd
}
