package audit

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// SDID constants for structured data IDs (RFC5424)
// Conjur's Private Enterprise Number is 43868
const (
	ConjurPEN   = 43868
	SDIDAuth    = "auth@43868"
	SDIDSubject = "subject@43868"
	SDIDAction  = "action@43868"
	SDIDClient  = "client@43868"
	SDIDPolicy  = "policy@43868"
)

// Syslog facility constants
const (
	FacilityAuth     = 4  // LOG_AUTH - security/authorization messages
	FacilityAuthPriv = 10 // LOG_AUTHPRIV - security/authorization messages (private)
)

// Severity levels matching syslog (RFC5424)
type Severity int

const (
	SeverityEmergency Severity = iota // 0
	SeverityAlert                     // 1
	SeverityCritical                  // 2
	SeverityError                     // 3
	SeverityWarning                   // 4
	SeverityNotice                    // 5
	SeverityInfo                      // 6
	SeverityDebug                     // 7
)

// Event represents an audit event
type Event interface {
	MessageID() string
	Message() string
	Severity() Severity
	Facility() int
	StructuredData() map[string]map[string]string
}

// Logger handles audit logging in RFC5424 syslog format
type Logger struct {
	writer   io.Writer
	hostname string
	appName  string
	pid      int
}

// NewLogger creates a new audit logger
func NewLogger() *Logger {
	hostname, _ := os.Hostname()
	return &Logger{
		writer:   os.Stdout,
		hostname: hostname,
		appName:  "conjur",
		pid:      os.Getpid(),
	}
}

// SetWriter sets the output writer for the logger
func (l *Logger) SetWriter(w io.Writer) {
	l.writer = w
}

// Log writes an audit event in RFC5424 syslog format
// Format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
func (l *Logger) Log(event Event) {
	// Calculate PRI value: facility * 8 + severity
	pri := event.Facility()*8 + int(event.Severity())

	// Format timestamp in RFC5424 format (ISO8601 with milliseconds)
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	// Format structured data
	sd := formatStructuredData(event.StructuredData())
	if sd == "" {
		sd = "-"
	}

	// Hostname (use "-" if not available)
	hostname := l.hostname
	if hostname == "" {
		hostname = "-"
	}

	// Build RFC5424 syslog message
	// <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
	logLine := fmt.Sprintf("<%d>1 %s %s %s %d %s %s %s\n",
		pri,
		timestamp,
		hostname,
		l.appName,
		l.pid,
		event.MessageID(),
		sd,
		event.Message(),
	)

	_, _ = l.writer.Write([]byte(logLine))
}

// formatStructuredData formats the structured data according to RFC5424
// Format: [sdid param1="value1" param2="value2"][sdid2 ...]
func formatStructuredData(sd map[string]map[string]string) string {
	if len(sd) == 0 {
		return ""
	}

	var parts []string
	for sdid, params := range sd {
		var paramParts []string
		paramParts = append(paramParts, sdid)
		for key, value := range params {
			// Escape special characters per RFC5424 section 6.3.3
			escaped := escapeSDValue(value)
			paramParts = append(paramParts, fmt.Sprintf("%s=%s", key, escaped))
		}
		parts = append(parts, "["+strings.Join(paramParts, " ")+"]")
	}
	return strings.Join(parts, "")
}

// escapeSDValue escapes special characters in structured data values per RFC5424
func escapeSDValue(value string) string {
	// Escape backslash, double quote, and closing bracket
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	value = strings.ReplaceAll(value, "]", "\\]")
	return "\"" + value + "\""
}

// Default logger instance
var DefaultLogger = NewLogger()

// Default store for database persistence (nil if AUDIT_DATABASE_URL not set)
var DefaultStore *Store

// Audit enabled state - defaults to true (enterprise feature)
// Can be disabled via CONJUR_AUDIT_ENABLED=false to mimic OSS behavior
var (
	auditEnabled     = true
	auditEnabledOnce sync.Once
	storeInitOnce    sync.Once
)

// IsEnabled returns whether audit logging is enabled
func IsEnabled() bool {
	auditEnabledOnce.Do(func() {
		if env := os.Getenv("CONJUR_AUDIT_ENABLED"); env != "" {
			auditEnabled = env != "false" && env != "0" && env != "no"
		}
	})
	return auditEnabled
}

// SetEnabled allows programmatic control of audit logging
// Note: This should be called before any Log calls for consistent behavior
func SetEnabled(enabled bool) {
	auditEnabled = enabled
}

// Log writes an event to the default logger and store (if audit is enabled)
func Log(event Event) {
	if !IsEnabled() {
		return
	}
	DefaultLogger.Log(event)

	// Initialize store on first use
	storeInitOnce.Do(func() {
		var err error
		DefaultStore, err = NewStore()
		if err != nil {
			// Log error but don't fail - audit DB is optional
			fmt.Fprintf(os.Stderr, "audit: failed to connect to audit database: %v\n", err)
		}
	})

	// Persist to database if store is available
	if DefaultStore != nil {
		if err := DefaultStore.Save(event); err != nil {
			fmt.Fprintf(os.Stderr, "audit: failed to save event: %v\n", err)
		}
	}
}
