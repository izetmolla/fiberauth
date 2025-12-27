package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/izetmolla/fiberauth"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Example demonstrating authentication lifecycle hooks

func main() {
	// Setup database
	db, err := gorm.Open(sqlite.Open("hooks_example.db"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	// Create auth instance
	auth, err := fiberauth.New(&fiberauth.Config{
		JWTSecret: "your-secret-key-change-in-production",
		DbClient:  db,
		Debug:     true,
	})
	if err != nil {
		log.Fatal(err)
	}

	// ============================================
	// Register Authentication Hooks
	// ============================================

	// Before Sign-In: Rate limiting and validation
	auth.OnBeforeSignIn(func(request *fiberauth.SignInRequest) error {
		log.Printf("[HOOK] BeforeSignIn: Attempting sign-in for %s", request.Email)

		// Example: Block specific emails
		if request.Email == "blocked@example.com" {
			return errors.New("this email is blocked")
		}

		// Example: Rate limiting check
		if isRateLimited(request.Email) {
			return errors.New("too many login attempts, please try again later")
		}

		return nil
	})

	// After Sign-In: Audit logging and analytics
	auth.OnAfterSignIn(func(user *fiberauth.User, response *fiberauth.AuthorizationResponse) error {
		log.Printf("[HOOK] AfterSignIn: User %s signed in successfully", user.Email)

		// Example: Track analytics (run in background)
		go func() {
			time.Sleep(100 * time.Millisecond) // Simulate API call
			log.Printf("[ANALYTICS] Tracked sign-in for user: %s", user.ID)
		}()

		return nil
	})

	// Before Sign-Up: Domain validation
	auth.OnBeforeSignUp(func(request *fiberauth.SignUpRequest) error {
		log.Printf("[HOOK] BeforeSignUp: Attempting sign-up for %s", request.Email)

		// Example: Email domain validation
		if !strings.HasSuffix(request.Email, "@example.com") {
			return errors.New("only @example.com email addresses are allowed")
		}

		// Example: Block specific emails
		if request.Email == "admin@example.com" {
			return errors.New("admin email cannot be used for registration")
		}

		return nil
	})

	// After Sign-Up: Welcome email and setup
	auth.OnAfterSignUp(func(user *fiberauth.User, response *fiberauth.AuthorizationResponse) error {
		log.Printf("[HOOK] AfterSignUp: New user registered: %s", user.Email)

		// Example: Send welcome email (run in background)
		go func() {
			if err := sendWelcomeEmail(user.Email, user.FirstName); err != nil {
				log.Printf("[ERROR] Failed to send welcome email: %v", err)
			} else {
				log.Printf("[EMAIL] Welcome email sent to: %s", user.Email)
			}
		}()

		return nil
	})

	// ============================================
	// Register User Lifecycle Hooks
	// ============================================

	// Before User Create: Set default values
	auth.OnBeforeUserCreate(func(user *fiberauth.User) error {
		log.Printf("[HOOK] BeforeUserCreate: Setting defaults for user %s", user.Email)

		// Set default metadata
		metadata := map[string]any{
			"source":      "api",
			"created_at":  time.Now().Format(time.RFC3339),
			"signup_ip":   "127.0.0.1", // In real app, get from request
			"newsletter":  false,
			"marketing":   false,
		}

		metadataJSON, err := json.Marshal(metadata)
		if err == nil {
			user.Metadata = json.RawMessage(metadataJSON)
		}

		// Set default roles for new users
		user.Roles = json.RawMessage(`["user"]`)

		return nil
	})

	// After User Create: Setup user resources
	auth.OnAfterUserCreate(func(user *fiberauth.User) error {
		log.Printf("[HOOK] AfterUserCreate: Setting up resources for user %s", user.ID)

		// Example: Create user profile (run in background)
		go func() {
			if err := createUserProfile(user.ID); err != nil {
				log.Printf("[ERROR] Failed to create user profile: %v", err)
			} else {
				log.Printf("[SUCCESS] User profile created for: %s", user.ID)
			}
		}()

		return nil
	})

	// ============================================
	// Register Token Hooks
	// ============================================

	// Before Token Generation: Add custom claims
	auth.OnBeforeTokenGeneration(func(user *fiberauth.User) (*fiberauth.Tokens, error) {
		log.Printf("[HOOK] BeforeTokenGeneration: Adding custom claims for user %s", user.ID)

		// Parse existing metadata
		var metadata map[string]any
		if len(user.Metadata) > 0 {
			json.Unmarshal(user.Metadata, &metadata)
		} else {
			metadata = make(map[string]any)
		}

		// Add custom claims
		metadata["department"] = getUserDepartment(user.ID)
		metadata["permissions"] = getUserPermissions(user.ID)
		metadata["token_generated_at"] = time.Now().Format(time.RFC3339)

		// Note: In a real implementation, you would modify the JWTOptions here
		// This is a simplified example

		return nil, nil
	})

	// After Token Generation: Track token creation
	auth.OnAfterTokenGeneration(func(user *fiberauth.User, tokens *fiberauth.Tokens) error {
		log.Printf("[HOOK] AfterTokenGeneration: Tokens generated for user %s", user.ID)

		// Example: Store token metadata for auditing
		go func() {
			storeTokenMetadata(user.ID, tokens.AccessToken, time.Now())
		}()

		return nil
	})

	// ============================================
	// Register Session Hooks
	// ============================================

	// Before Session Create: Validate session creation
	auth.OnBeforeSessionCreate(func(user *fiberauth.User, ipAddress string) error {
		log.Printf("[HOOK] BeforeSessionCreate: Validating session for user %s from IP %s", user.ID, ipAddress)

		// Example: Check device limits
		if hasTooManyActiveSessions(user.ID) {
			return errors.New("too many active sessions")
		}

		return nil
	})

	// After Session Create: Track session creation
	auth.OnAfterSessionCreate(func(session *fiberauth.SessionData) error {
		log.Printf("[HOOK] AfterSessionCreate: Session %s created for user %s", session.ID, session.UserID)

		// Example: Track session analytics
		go func() {
			trackSessionCreation(session.UserID, session.ID)
		}()

		return nil
	})

	// ============================================
	// Setup Fiber Application
	// ============================================

	app := fiber.New()

	// Health check
	app.Get("/health", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	// Authentication routes
	app.Post("/auth/signup", auth.SignUpController)
	app.Post("/auth/signin", auth.SignInController)
	app.Post("/auth/signout", auth.SignOutController)
	app.Post("/auth/refresh", auth.HandleRefreshTokenController)

	// Protected route
	app.Get("/profile", auth.UseAuth(&fiberauth.AuthConfig{
		OnlyAPI: true,
	}), func(c fiber.Ctx) error {
		userClaims, err := fiberauth.GetUser(c.Locals("user"))
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"user": userClaims,
		})
	})

	// Start server
	log.Println("Server starting on http://localhost:3000")
	log.Println("Hooks registered and ready!")
	log.Fatal(app.Listen(":3000"))
}

// ============================================
// Helper Functions (Mock Implementations)
// ============================================

var rateLimitStore = make(map[string]int)
var sessionCount = make(map[string]int)

func isRateLimited(email string) bool {
	count := rateLimitStore[email]
	if count >= 5 {
		return true
	}
	rateLimitStore[email] = count + 1
	return false
}

func sendWelcomeEmail(email, firstName string) error {
	// Simulate email sending
	time.Sleep(50 * time.Millisecond)
	log.Printf("[EMAIL] Sending welcome email to %s (%s)", email, firstName)
	return nil
}

func createUserProfile(userID string) error {
	// Simulate profile creation
	time.Sleep(100 * time.Millisecond)
	log.Printf("[PROFILE] Creating profile for user: %s", userID)
	return nil
}

func getUserDepartment(userID string) string {
	// Mock implementation
	return "engineering"
}

func getUserPermissions(userID string) []string {
	// Mock implementation
	return []string{"read", "write"}
}

func storeTokenMetadata(userID, token string, timestamp time.Time) {
	// Simulate storing token metadata
	log.Printf("[AUDIT] Stored token metadata for user: %s at %s", userID, timestamp.Format(time.RFC3339))
}

func hasTooManyActiveSessions(userID string) bool {
	count := sessionCount[userID]
	return count >= 3
}

func trackSessionCreation(userID, sessionID string) {
	// Simulate analytics tracking
	log.Printf("[ANALYTICS] Tracked session creation: user=%s, session=%s", userID, sessionID)
}

/*
Example Usage:

1. Sign Up (will trigger BeforeSignUp, BeforeUserCreate, AfterUserCreate, AfterSignUp hooks):
   curl -X POST http://localhost:3000/auth/signup \
     -H "Content-Type: application/json" \
     -d '{
       "email": "john@example.com",
       "password": "securepassword123",
       "first_name": "John",
       "last_name": "Doe"
     }'

2. Sign In (will trigger BeforeSignIn, AfterSignIn hooks):
   curl -X POST http://localhost:3000/auth/signin \
     -H "Content-Type: application/json" \
     -d '{
       "email": "john@example.com",
       "password": "securepassword123"
     }'

3. Access Protected Route:
   curl http://localhost:3000/profile \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

Watch the console logs to see hooks being executed!
*/

