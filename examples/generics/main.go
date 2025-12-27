package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/izetmolla/fiberauth"
	"github.com/izetmolla/fiberauth/pkg/storage/models"
	"github.com/izetmolla/fiberauth/pkg/storage/redis"
	"github.com/izetmolla/fiberauth/pkg/utils"
)

// Example demonstrating generic utility functions

func main() {
	fmt.Println("=== Generic Utilities Examples ===\n")

	// ============================================
	// Example 1: Convert between compatible types
	// ============================================
	fmt.Println("1. Type Conversion with Convert[TFrom, TTo]")
	fmt.Println("--------------------------------------------")

	// Create a SessionData instance
	sessionData := &fiberauth.SessionData{
		ID:       "session-123",
		UserID:   "user-456",
		Roles:    json.RawMessage(`["admin", "user"]`),
		Metadata: json.RawMessage(`{"source": "web"}`),
		Options:  json.RawMessage(`{"theme": "dark"}`),
	}

	fmt.Printf("Original SessionData: %+v\n", sessionData)

	// Convert to redis.SessionData using generics
	redisSession, err := utils.Convert[fiberauth.SessionData, redis.SessionData](sessionData)
	if err != nil {
		log.Fatalf("Conversion error: %v", err)
	}

	fmt.Printf("Converted to Redis SessionData: %+v\n", redisSession)
	fmt.Println()

	// ============================================
	// Example 2: Ensure JSON fields have defaults
	// ============================================
	fmt.Println("2. Ensuring JSON Fields with EnsureJSON[T]")
	fmt.Println("--------------------------------------------")

	var user models.User

	// User with empty JSON fields
	user.Roles = json.RawMessage(``)
	user.Metadata = json.RawMessage(``)
	user.Options = json.RawMessage(``)

	fmt.Printf("User with empty fields:\n")
	fmt.Printf("  Roles (empty): %s\n", string(user.Roles))
	fmt.Printf("  Metadata (empty): %s\n", string(user.Metadata))
	fmt.Printf("  Options (empty): %s\n", string(user.Options))

	// Ensure fields have defaults
	roles := utils.EnsureJSON(user.Roles, []string{})
	metadata := utils.EnsureJSON(user.Metadata, map[string]any{})
	options := utils.EnsureJSON(user.Options, map[string]any{})

	fmt.Printf("\nAfter EnsureJSON:\n")
	fmt.Printf("  Roles: %s\n", string(roles))
	fmt.Printf("  Metadata: %s\n", string(metadata))
	fmt.Printf("  Options: %s\n", string(options))
	fmt.Println()

	// User with existing JSON fields
	user.Roles = json.RawMessage(`["admin", "moderator"]`)
	user.Metadata = json.RawMessage(`{"key": "value"}`)

	roles = utils.EnsureJSON(user.Roles, []string{})
	metadata = utils.EnsureJSON(user.Metadata, map[string]any{})

	fmt.Printf("User with existing fields:\n")
	fmt.Printf("  Roles: %s\n", string(roles))
	fmt.Printf("  Metadata: %s\n", string(metadata))
	fmt.Println()

	// ============================================
	// Example 3: Parse JSON with defaults
	// ============================================
	fmt.Println("3. Parsing JSON with ParseJSON[T]")
	fmt.Println("--------------------------------------------")

	// Parse roles JSON
	rolesJSON := json.RawMessage(`["admin", "user", "moderator"]`)
	parsedRoles := utils.ParseJSON[[]string](rolesJSON, []string{})
	fmt.Printf("Parsed roles: %v\n", parsedRoles)

	// Parse metadata JSON
	metadataJSON := json.RawMessage(`{"department": "engineering", "level": "senior"}`)
	parsedMetadata := utils.ParseJSON[map[string]any](metadataJSON, map[string]any{})
	fmt.Printf("Parsed metadata: %v\n", parsedMetadata)

	// Parse with empty/invalid JSON (returns default)
	emptyJSON := json.RawMessage(``)
	defaultRoles := utils.ParseJSON[[]string](emptyJSON, []string{})
	fmt.Printf("Parsed empty JSON (default): %v\n", defaultRoles)

	invalidJSON := json.RawMessage(`{"invalid": json}`)
	safeRoles := utils.ParseJSON[[]string](invalidJSON, []string{})
	fmt.Printf("Parsed invalid JSON (default): %v\n", safeRoles)
	fmt.Println()

	// ============================================
	// Example 4: Real-world usage pattern
	// ============================================
	fmt.Println("4. Real-world Usage Pattern")
	fmt.Println("--------------------------------------------")

	// Simulate creating session data from user
	user = models.User{
		ID:       "user-123",
		Email:    "user@example.com",
		Roles:    json.RawMessage(`["admin"]`),
		Metadata: json.RawMessage(`{"source": "api"}`),
		Options:  json.RawMessage(``), // Empty field
	}

	sessionDataFromUser := &fiberauth.SessionData{
		ID:       "session-789",
		UserID:   user.ID,
		Roles:    utils.EnsureJSON(user.Roles, []string{}),
		Metadata: utils.EnsureJSON(user.Metadata, map[string]any{}),
		Options:  utils.EnsureJSON(user.Options, map[string]any{}),
	}

	fmt.Printf("Created SessionData from User:\n")
	fmt.Printf("  ID: %s\n", sessionDataFromUser.ID)
	fmt.Printf("  UserID: %s\n", sessionDataFromUser.UserID)
	fmt.Printf("  Roles: %s\n", string(sessionDataFromUser.Roles))
	fmt.Printf("  Metadata: %s\n", string(sessionDataFromUser.Metadata))
	fmt.Printf("  Options: %s (default applied)\n", string(sessionDataFromUser.Options))

	// Convert to Redis format for caching
	redisSessionData, err := utils.Convert[fiberauth.SessionData, redis.SessionData](sessionDataFromUser)
	if err != nil {
		log.Fatalf("Conversion error: %v", err)
	}

	fmt.Printf("\nConverted to Redis format for caching:\n")
	fmt.Printf("  ID: %s\n", redisSessionData.ID)
	fmt.Printf("  UserID: %s\n", redisSessionData.UserID)
	fmt.Printf("  Roles: %s\n", string(redisSessionData.Roles))

	// Parse roles for business logic
	rolesList := utils.ParseJSON[[]string](redisSessionData.Roles, []string{})
	fmt.Printf("\nParsed roles for business logic: %v\n", rolesList)

	if len(rolesList) > 0 {
		fmt.Printf("User has roles: %v\n", rolesList)
		for _, role := range rolesList {
			fmt.Printf("  - %s\n", role)
		}
	}

	fmt.Println("\n=== Examples Complete ===")
}

/*
Output Example:

=== Generic Utilities Examples ===

1. Type Conversion with Convert[TFrom, TTo]
--------------------------------------------
Original SessionData: &{ID:session-123 UserID:user-456 Roles:[91 34 97 100 109 105 110 34 44 32 34 117 115 101 114 34 93] Metadata:[123 34 115 111 117 114 99 101 34 58 32 34 119 101 98 34 125] Options:[123 34 116 104 101 109 101 34 58 32 34 100 97 114 107 34 125]}
Converted to Redis SessionData: &{ID:session-123 UserID:user-456 Roles:[91 34 97 100 109 105 110 34 44 32 34 117 115 101 114 34 93] Metadata:[123 34 115 111 117 114 99 101 34 58 32 34 119 101 98 34 125] Options:[123 34 116 104 101 109 101 34 58 32 34 100 97 114 107 34 125]}

2. Ensuring JSON Fields with EnsureJSON[T]
--------------------------------------------
User with empty fields:
  Roles (empty):
  Metadata (empty):
  Options (empty):

After EnsureJSON:
  Roles: []
  Metadata: {}
  Options: {}

User with existing fields:
  Roles: ["admin","moderator"]
  Metadata: {"key":"value"}

3. Parsing JSON with ParseJSON[T]
--------------------------------------------
Parsed roles: [admin user moderator]
Parsed metadata: map[department:engineering level:senior]
Parsed empty JSON (default): []
Parsed invalid JSON (default): []

4. Real-world Usage Pattern
--------------------------------------------
Created SessionData from User:
  ID: session-789
  UserID: user-123
  Roles: ["admin"]
  Metadata: {"source":"api"}
  Options: {} (default applied)

Converted to Redis format for caching:
  ID: session-789
  UserID: user-123
  Roles: ["admin"]

Parsed roles for business logic: [admin]

User has roles: [admin]
  - admin

=== Examples Complete ===
*/

