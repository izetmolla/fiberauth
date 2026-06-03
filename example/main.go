// Command backend is the API server for the goauth full-stack example. It uses
// Fiber v3 + goauth (via the fiberauth adapter) with an in-memory user store
// (no real database) and exposes public, private (any signed-in user) and
// admin-only routes.
//
// Auth uses the token (bearer) flow so the React SPA can store tokens and send
// them via the Authorization header.
package main

import (
	"context"
	"crypto/subtle"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"

	"github.com/izetmolla/fiberauth"
	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/adapters/memory"
	"github.com/izetmolla/goauth/providers/credentials"
)

// account is a demo user record held entirely in memory.
type account struct {
	ID       string
	Name     string
	Email    string
	Password string
	Roles    []string
}

// userStore is our "database": a plain in-memory map keyed by email.
var userStore = map[string]*account{
	"alice@example.com": {ID: "u_alice", Name: "Alice", Email: "alice@example.com", Password: "password", Roles: []string{"user"}},
	"bob@example.com":   {ID: "u_bob", Name: "Bob", Email: "bob@example.com", Password: "password", Roles: []string{"user"}},
	"admin@example.com": {ID: "u_admin", Name: "Admin", Email: "admin@example.com", Password: "password", Roles: []string{"user", "admin"}},
}

func findByEmail(email string) *account { return userStore[email] }

func findByID(id string) *account {
	for _, a := range userStore {
		if a.ID == id {
			return a
		}
	}
	return nil
}

func main() {
	auth, err := goauth.New(goauth.Config{
		Secret:    []string{getenv("AUTH_SECRET", "f4d8f5b2c1e7a9d34b6f8e2c7a1d9f5b8c3e6a7d2f1b9c4e8a5d7f3c1b6e9a2")},
		Session:   goauth.SessionConfig{Strategy: goauth.StrategyJWT},
		TrustHost: true,
		// The email/OTP provider persists its verification codes via the adapter.
		// In-memory is fine for a demo (credentials still uses the JWT strategy).
		Adapter: memory.New(),
		// Token (bearer) flow for the SPA. Short-lived access token (60s) so the
		// refresh path is easy to observe; long-lived refresh token (1 year).
		Tokens: goauth.TokensConfig{
			Enabled:            true,
			AlwaysReturn:       true,
			AccessTokenMaxAge:  60 * time.Second,
			RefreshTokenMaxAge: 365 * 24 * time.Hour,
		},
		Providers: []goauth.Provider{
			credentials.New(credentials.Options{
				Fields: []goauth.CredentialField{
					{Name: "email", Label: "Email", Type: "email"},
					{Name: "password", Label: "Password", Type: "password"},
				},
				Authorize: func(_ context.Context, c map[string]string, _ *http.Request) (*goauth.User, error) {
					acc := findByEmail(c["email"])
					if acc == nil {
						return nil, nil
					}
					// Constant-time password comparison (demo passwords only).
					if subtle.ConstantTimeCompare([]byte(acc.Password), []byte(c["password"])) != 1 {
						return nil, nil
					}
					return &goauth.User{ID: acc.ID, Name: acc.Name, Email: acc.Email}, nil
				},
			}),

			// Email one-time-code (OTP) provider — SIMULATED.
			//
			// This is the otp.New(...) provider expanded inline so we can pin the
			// generated code to a fixed value for the demo: instead of a random
			// 6-digit code, GenerateVerificationToken always returns "123456".
			// SendVerificationRequest just logs the code instead of sending email.
			//
			//   1. POST /auth/signin/otp     email=alice@example.com   -> "sends" the code
			//   2. POST /auth/callback/otp   email=alice@example.com&code=123456  -> signs in
			&goauth.EmailProvider{
				ProviderID:                "otp",
				DisplayName:               "Email code",
				MaxAge:                    600, // code valid for 10 minutes
				GenerateVerificationToken: func() string { return "123456" },
				SendVerificationRequest: func(_ context.Context, p goauth.SendVerificationRequestParams) error {
					log.Printf("[email-otp] (simulated) to %s -> verification code: %s", p.Identifier, p.Token)
					return nil
				},
			},
		},
		Callbacks: goauth.Callbacks{
			// Attach roles from the store so guards can read session.Roles().
			JWT: func(_ context.Context, p goauth.JWTCallbackParams) (goauth.JWT, error) {
				if p.User != nil {
					// Credentials sign-in matches by ID; OTP sign-in matches by email.
					acc := findByID(p.User.ID)
					if acc == nil {
						acc = findByEmail(p.User.Email)
					}
					if acc != nil {
						p.Token["roles"] = acc.Roles
					}
				}
				return p.Token, nil
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	app := fiber.New()
	app.Use(logger.New())
	// No CORS middleware needed: in dev the Vite server proxies /api and /auth to
	// this backend, so requests are same-origin (see frontend/vite.config.ts).

	// goauth action routes: /auth/session, /auth/callback/credentials, /auth/token, ...
	app.All("/auth/*", fiberauth.Handler(auth))

	// --- Public: no authentication required.
	app.Get("/api/public", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"area":    "public",
			"message": "Anyone can see this. No login required.",
		})
	})

	// --- Private: any authenticated user.
	app.Get("/api/me", fiberauth.Protect(auth), func(c fiber.Ctx) error {
		s := fiberauth.SessionFrom(c)
		return c.JSON(fiber.Map{"user": s.User, "roles": s.Roles()})
	})
	app.Get("/api/private", fiberauth.Protect(auth), func(c fiber.Ctx) error {
		s := fiberauth.SessionFrom(c)
		return c.JSON(fiber.Map{
			"area":    "private",
			"message": "Welcome to your dashboard, " + s.User.Name + ".",
		})
	})

	// --- Admin: requires the "admin" role.
	admin := app.Group("/api/admin", fiberauth.Guard(auth, fiberauth.HasRole("admin")))
	admin.Get("/", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"area": "admin", "message": "Admin control panel."})
	})
	admin.Get("/users", func(c fiber.Ctx) error {
		out := make([]fiber.Map, 0, len(userStore))
		for _, a := range userStore {
			out = append(out, fiber.Map{"id": a.ID, "name": a.Name, "email": a.Email, "roles": a.Roles})
		}
		return c.JSON(fiber.Map{"users": out})
	})

	addr := getenv("ADDR", "0.0.0.0:3009")
	log.Printf("goauth fiber_example backend listening on %s", addr)
	log.Fatal(app.Listen(addr))
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
