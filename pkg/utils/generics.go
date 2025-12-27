// Package utils provides generic utility functions for type conversions and JSON handling.
package utils

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Convert converts between two compatible types using JSON marshaling/unmarshaling.
// This is useful for converting between similar struct types (e.g., SessionData to redis.SessionData).
//
// Parameters:
//   - from: Source value to convert
//
// Returns:
//   - *TTo: Converted value of target type
//   - error: Error if conversion fails
//
// Example:
//
//	redisSession, err := Convert[SessionData, redis.SessionData](sessionData)
func Convert[TFrom, TTo any](from *TFrom) (*TTo, error) {
	if from == nil {
		return nil, errors.New("source cannot be nil")
	}

	// Use JSON marshaling/unmarshaling for deep copy
	data, err := json.Marshal(from)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal: %w", err)
	}

	var to TTo
	if err := json.Unmarshal(data, &to); err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}

	return &to, nil
}

// EnsureJSON ensures a JSON field is not empty, returning a default value if needed.
//
// Parameters:
//   - field: JSON raw message to check
//   - defaultValue: Default value to use if field is empty
//
// Returns:
//   - json.RawMessage: The field if non-empty, or marshaled default value
//
// Example:
//
//	roles := EnsureJSON(user.Roles, []string{})
//	metadata := EnsureJSON(user.Metadata, map[string]any{})
func EnsureJSON[T any](field json.RawMessage, defaultValue T) json.RawMessage {
	if len(field) == 0 {
		data, _ := json.Marshal(defaultValue)
		return json.RawMessage(data)
	}
	return field
}

// ParseJSON parses a JSON raw message into the target type with a default fallback.
//
// Parameters:
//   - data: JSON raw message to parse
//   - defaultValue: Default value if parsing fails or data is empty
//
// Returns:
//   - T: Parsed value or default value
//
// Example:
//
//	roles := ParseJSON[[]string](user.Roles, []string{})
//	metadata := ParseJSON[map[string]any](user.Metadata, map[string]any{})
func ParseJSON[T any](data json.RawMessage, defaultValue T) T {
	if len(data) == 0 {
		return defaultValue
	}

	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		return defaultValue
	}

	return result
}
