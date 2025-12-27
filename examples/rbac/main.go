// Package main demonstrates Role-Based Access Control (RBAC) with FiberAuth.
// This example shows how to implement fine-grained access control using roles.
package main

import (
	"encoding/json"
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

	// 2. Initialize FiberAuth
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
		AppName: "RBAC Example",
	})

	// 4. Public routes
	app.Get("/", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "Role-Based Access Control Example",
			"roles": fiber.Map{
				"user":       "Basic user access",
				"moderator":  "Can moderate content",
				"admin":      "Full admin access",
				"superadmin": "System administrator",
			},
		})
	})

	// 5. Auth routes
	app.Post("/auth/signup", func(c fiber.Ctx) error {
		type SignUpWithRole struct {
			Email     string   `json:"email"`
			Password  string   `json:"password"`
			FirstName string   `json:"first_name"`
			LastName  string   `json:"last_name"`
			Roles     []string `json:"roles"` // Custom field for this example
		}

		var req SignUpWithRole
		if err := c.Bind().Body(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Default to user role if no roles specified
		if len(req.Roles) == 0 {
			req.Roles = []string{"user"}
		}

		// Create user with roles
		response, errFields := auth.SignUp(&fiberauth.SignUpRequest{
			Email:     req.Email,
			Password:  req.Password,
			FirstName: req.FirstName,
			LastName:  req.LastName,
		})
		if errFields != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": errFields.Error.Error(),
			})
		}

		// Update user roles (in real app, do this in database)
		log.Printf("User created with roles: %v", req.Roles)

		return c.JSON(response)
	})

	app.Post("/auth/signin", auth.SignInController)
	app.Post("/auth/signout", auth.SignOutController)

	// 6. Public API (no authentication required)
	publicAPI := app.Group("/api/public")
	publicAPI.Get("/posts", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"posts": []fiber.Map{
				{"id": 1, "title": "Public Post 1"},
				{"id": 2, "title": "Public Post 2"},
			},
		})
	})

	// 7. User-only routes (any authenticated user)
	userAPI := app.Group("/api/user")
	userAPI.Use(auth.UseAuth(&fiberauth.AuthConfig{
		OnlyAPI: true,
	}))

	userAPI.Get("/profile", func(c fiber.Ctx) error {
		userClaims, err := fiberauth.GetUser(c.Locals("user"))
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		var roles []string
		if err := json.Unmarshal(userClaims.Roles, &roles); err != nil {
			roles = []string{}
		}

		return c.JSON(fiber.Map{
			"user_id": userClaims.UserID,
			"roles":   roles,
		})
	})

	userAPI.Post("/posts", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "Post created (user access)",
		})
	})

	// 8. Moderator routes (moderator or admin only)
	modAPI := app.Group("/api/moderator")
	modAPI.Use(auth.UseAuth(&fiberauth.AuthConfig{
		OnlyAPI: true,
		Roles:   []string{"moderator", "admin", "superadmin"},
	}))

	modAPI.Delete("/posts/:id", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "Post deleted (moderator access)",
			"post_id": c.Params("id"),
		})
	})

	modAPI.Put("/posts/:id/flag", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "Post flagged (moderator access)",
			"post_id": c.Params("id"),
		})
	})

	// 9. Admin routes (admin or superadmin only)
	adminAPI := app.Group("/api/admin")
	adminAPI.Use(auth.UseAuth(&fiberauth.AuthConfig{
		OnlyAPI: true,
		Roles:   []string{"admin", "superadmin"},
	}))

	adminAPI.Get("/users", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "List all users (admin access)",
			"users":   []string{"user1", "user2", "user3"},
		})
	})

	adminAPI.Put("/users/:id/roles", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "User roles updated (admin access)",
			"user_id": c.Params("id"),
		})
	})

	// 10. Superadmin routes (superadmin only)
	superadminAPI := app.Group("/api/superadmin")
	superadminAPI.Use(auth.UseAuth(&fiberauth.AuthConfig{
		OnlyAPI: true,
		Roles:   []string{"superadmin"},
	}))

	superadminAPI.Get("/system/config", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "System configuration (superadmin access)",
			"config": fiber.Map{
				"version": "1.0.0",
				"mode":    "production",
			},
		})
	})

	superadminAPI.Post("/system/maintenance", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "Maintenance mode toggled (superadmin access)",
		})
	})

	// 11. Custom role checking middleware
	app.Get("/api/custom-check", auth.UseAuthorization(), func(c fiber.Ctx) error {
		userClaims, err := fiberauth.GetUser(c.Locals("user"))
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		var roles []string
		if err := json.Unmarshal(userClaims.Roles, &roles); err != nil {
			roles = []string{}
		}

		// Custom role logic
		hasSpecialAccess := false
		for _, role := range roles {
			if role == "admin" || role == "special" {
				hasSpecialAccess = true
				break
			}
		}

		if !hasSpecialAccess {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Special access required",
			})
		}

		return c.JSON(fiber.Map{
			"message": "Custom role check passed",
		})
	})

	// 12. Start server
	log.Println("Server starting on http://localhost:3000")
	log.Println("\nRole Hierarchy:")
	log.Println("  user       -> Basic access")
	log.Println("  moderator  -> User + Moderation")
	log.Println("  admin      -> Moderator + Administration")
	log.Println("  superadmin -> Admin + System Management")
	log.Fatal(app.Listen(":3000"))
}

/*
Example Usage:

1. Create a regular user:
curl -X POST http://localhost:3000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123",
    "first_name": "Regular",
    "last_name": "User",
    "roles": ["user"]
  }'

2. Create an admin user:
curl -X POST http://localhost:3000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "admin123",
    "first_name": "Admin",
    "last_name": "User",
    "roles": ["admin"]
  }'

3. Sign in and get token:
curl -X POST http://localhost:3000/auth/signin \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'

4. Access user endpoint (works for all authenticated users):
curl http://localhost:3000/api/user/profile \
  -H "Authorization: Bearer USER_TOKEN"

5. Try to access moderator endpoint (will fail for regular users):
curl http://localhost:3000/api/moderator/posts/1 \
  -X DELETE \
  -H "Authorization: Bearer USER_TOKEN"

6. Access admin endpoint (requires admin/superadmin role):
curl http://localhost:3000/api/admin/users \
  -H "Authorization: Bearer ADMIN_TOKEN"

Role Hierarchy in Action:
- /api/public/*      -> Anyone (no auth)
- /api/user/*        -> user, moderator, admin, superadmin
- /api/moderator/*   -> moderator, admin, superadmin
- /api/admin/*       -> admin, superadmin
- /api/superadmin/*  -> superadmin only
*/
