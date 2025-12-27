// Package fiberauth provides test helpers for backward compatibility
// These are exported for testing purposes only and should not be used in production code
package fiberauth

import (
	"encoding/json"
)

// Test helper functions that were moved to internal packages
// These are exported here for backward compatibility with existing tests

// HasRequiredRole checks if a user has the required roles (exported for testing)
func HasRequiredRole(requiredRoles []string, userRoles []string) bool {
	if len(requiredRoles) == 0 {
		return true
	}

	for _, requiredRole := range requiredRoles {
		for _, userRole := range userRoles {
			if userRole == requiredRole {
				return true
			}
		}
	}

	return false
}

// HasRequiredRoleFromJSON checks if a user has required roles from JSON (exported for testing)
func HasRequiredRoleFromJSON(requiredRoles []string, userRoles json.RawMessage) bool {
	if len(requiredRoles) == 0 {
		return true
	}

	var roles []string
	if err := json.Unmarshal(userRoles, &roles); err != nil {
		return false
	}

	return HasRequiredRole(requiredRoles, roles)
}

// EnsureJSONField ensures a JSON field is not nil (exported for testing)
func EnsureJSONField(field json.RawMessage, defaultValue string) json.RawMessage {
	if len(field) == 0 {
		return json.RawMessage(defaultValue)
	}
	return field
}

