// Package main demonstrates minimal FiberAuth setup without Redis or Social providers.
// This example shows the bare minimum required to use FiberAuth for authentication.
package main

import (
	"log"

	"github.com/gofiber/fiber/v3"
	"github.com/izetmolla/fiberauth"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	// 1. Initialize database
	db, err := gorm.Open(sqlite.Open("auth.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// 2. Initialize FiberAuth with minimal configuration
	auth, err := fiberauth.New(&fiberauth.Config{
		JWTSecret: "your-secret-key-change-in-production",
		DbClient:  db,
		Debug:     true,
	})
	if err != nil {
		log.Fatal("Failed to initialize auth:", err)
	}

	// 3. Create Fiber app
	app := fiber.New(fiber.Config{
		AppName: "Minimal FiberAuth Example",
	})

	// 4. Public routes
	app.Get("/", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "Welcome to FiberAuth Minimal Example",
			"routes": fiber.Map{
				"signup": "POST /auth/signup",
				"signin": "POST /auth/signin",
				"me":     "GET /api/me (requires auth)",
			},
		})
	})

	// 5. Auth routes
	app.Post("/auth/signup", auth.SignUpController)
	app.Post("/auth/signin", auth.SignInController)
	app.Post("/auth/signout", auth.SignOutController)
	app.Post("/auth/refresh", auth.HandleRefreshTokenController)

	// 6. Protected routes
	api := app.Group("/api")
	api.Use(auth.UseAuth(&fiberauth.AuthConfig{
		OnlyAPI: true, // JWT-based authentication
	}))

	api.Get("/me", func(c fiber.Ctx) error {
		// Extract user claims from JWT token
		userClaims, err := fiberauth.GetUser(c.Locals("user"))
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"user": fiber.Map{
				"id":       userClaims.UserID,
				"roles":    userClaims.Roles,
				"metadata": userClaims.Metadata,
			},
		})
	})

	// 7. Start server
	log.Println("Server starting on http://localhost:3000")
	log.Fatal(app.Listen(":3000"))
}

/*
Example Usage:

1. Sign Up:
curl -X POST http://localhost:3000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123",
    "first_name": "John",
    "last_name": "Doe"
  }'

Response:
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "roles": [],
    "metadata": {}
  },
  "tokens": {
    "access_token": "eyJhbGc...",
    "refresh_token": "eyJhbGc..."
  },
  "session_id": "uuid"
}

2. Sign In:
curl -X POST http://localhost:3000/auth/signin \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'

3. Access Protected Route:
curl http://localhost:3000/api/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

4. Refresh Token:
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -H "cft: t" \
  -d '{"refresh_token": "YOUR_REFRESH_TOKEN"}'
*/

