// Package utils provides logging utilities
package utils

import (
	"fmt"
	"log"
	"time"
)

// Logger defines the logging interface for FiberAuth
// This allows users to plug in their own logging implementation
type Logger interface {
	Info(message string, fields ...interface{})
	Warn(message string, fields ...interface{})
	Error(message string, fields ...interface{})
	Debug(message string, fields ...interface{})
}

// DefaultLogger is a simple logger that writes to stdout
type DefaultLogger struct {
	debug bool
}

// NewDefaultLogger creates a new default logger
func NewDefaultLogger(debug bool) *DefaultLogger {
	return &DefaultLogger{debug: debug}
}

// Info logs an info message
func (l *DefaultLogger) Info(message string, fields ...interface{}) {
	log.Printf("[INFO] %s %v\n", message, fields)
}

// Warn logs a warning message
func (l *DefaultLogger) Warn(message string, fields ...interface{}) {
	log.Printf("[WARN] %s %v\n", message, fields)
}

// Error logs an error message
func (l *DefaultLogger) Error(message string, fields ...interface{}) {
	log.Printf("[ERROR] %s %v\n", message, fields)
}

// Debug logs a debug message (only if debug mode is enabled)
func (l *DefaultLogger) Debug(message string, fields ...interface{}) {
	if l.debug {
		log.Printf("[DEBUG] %s %v\n", message, fields)
	}
}

// NoOpLogger is a logger that doesn't log anything
type NoOpLogger struct{}

// NewNoOpLogger creates a new no-op logger
func NewNoOpLogger() *NoOpLogger {
	return &NoOpLogger{}
}

func (l *NoOpLogger) Info(message string, fields ...interface{})  {}
func (l *NoOpLogger) Warn(message string, fields ...interface{})  {}
func (l *NoOpLogger) Error(message string, fields ...interface{}) {}
func (l *NoOpLogger) Debug(message string, fields ...interface{}) {}

// AuditLogger logs authentication events for security auditing
type AuditLogger struct {
	logger Logger
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(logger Logger) *AuditLogger {
	return &AuditLogger{logger: logger}
}

// LogSignIn logs a sign-in event
func (a *AuditLogger) LogSignIn(userID, email, ip string, success bool) {
	status := "SUCCESS"
	if !success {
		status = "FAILED"
	}
	
	a.logger.Info(
		fmt.Sprintf("SignIn %s", status),
		"user_id", userID,
		"email", email,
		"ip", ip,
		"timestamp", time.Now().Format(time.RFC3339),
	)
}

// LogSignUp logs a sign-up event
func (a *AuditLogger) LogSignUp(userID, email, ip string) {
	a.logger.Info(
		"SignUp",
		"user_id", userID,
		"email", email,
		"ip", ip,
		"timestamp", time.Now().Format(time.RFC3339),
	)
}

// LogSignOut logs a sign-out event
func (a *AuditLogger) LogSignOut(userID string) {
	a.logger.Info(
		"SignOut",
		"user_id", userID,
		"timestamp", time.Now().Format(time.RFC3339),
	)
}

// LogUnauthorizedAccess logs an unauthorized access attempt
func (a *AuditLogger) LogUnauthorizedAccess(ip, path, reason string) {
	a.logger.Warn(
		"Unauthorized Access",
		"ip", ip,
		"path", path,
		"reason", reason,
		"timestamp", time.Now().Format(time.RFC3339),
	)
}

