// Package main demonstrates FiberAuth with Redis caching.
// This example shows how to use Redis for session caching to improve performance.
package main

import (
	"context"
	"log"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/izetmolla/fiberauth"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	// 1. Initialize PostgreSQL database
	dsn := "host=localhost user=postgres password=postgres dbname=auth port=5432 sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// 2. Initialize Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	// Test Redis connection
	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatal("Failed to connect to Redis:", err)
	}

	// 3. Initialize FiberAuth with Redis caching
	redisTTL := 30 * time.Minute
	auth, err := fiberauth.New(&fiberauth.Config{
		JWTSecret:      "your-secret-key-change-in-production",
		DbClient:       db,
		RedisClient:    rdb,
		RedisKeyPrefix: "auth:sessions",
		RedisTTL:       &redisTTL,
		Debug:          true,
	})
	if err != nil {
		log.Fatal("Failed to initialize auth:", err)
	}

	// 4. Create Fiber app
	app := fiber.New(fiber.Config{
		AppName: "FiberAuth with Redis Example",
	})

	// 5. Public routes
	app.Get("/", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "FiberAuth with Redis Caching",
			"features": []string{
				"PostgreSQL for persistent storage",
				"Redis for session caching",
				"JWT token authentication",
				"Session-based authentication",
			},
		})
	})

	// 6. Auth routes
	app.Post("/auth/signup", auth.SignUpController)
	app.Post("/auth/signin", auth.SignInController)
	app.Post("/auth/signout", auth.SignOutController)
	app.Post("/auth/refresh", auth.HandleRefreshTokenController)

	// 7. API routes with JWT authentication
	api := app.Group("/api")
	api.Use(auth.UseAuth(&fiberauth.AuthConfig{
		OnlyAPI: true,
	}))

	api.Get("/profile", func(c fiber.Ctx) error {
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

	// 8. Web routes with session-based authentication
	web := app.Group("/web")
	web.Use(auth.UseAuth(&fiberauth.AuthConfig{
		OnlyAPI:          false,
		RedirectToSignIn: true,
	}))

	web.Get("/dashboard", func(c fiber.Ctx) error {
		sessionID := auth.GetSessionID(c)
		session, err := auth.GetSession(sessionID)
		if err != nil {
			return c.Redirect().To("/auth/signin")
		}

		return c.JSON(fiber.Map{
			"message":    "Dashboard",
			"user_id":    session.UserID,
			"session_id": session.ID,
			"cached":     "Session cached in Redis for fast access",
		})
	})

	// 9. Admin routes with role-based access
	admin := app.Group("/admin")
	admin.Use(auth.UseAuth(&fiberauth.AuthConfig{
		OnlyAPI: true,
		Roles:   []string{"admin", "superadmin"},
	}))

	admin.Get("/users", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "List all users (admin only)",
		})
	})

	// 10. Start server
	log.Println("Server starting on http://localhost:3000")
	log.Println("Redis caching enabled for sessions")
	log.Fatal(app.Listen(":3000"))
}

/*
Example Usage:

1. Sign Up:
curl -X POST http://localhost:3000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "admin123",
    "first_name": "Admin",
    "last_name": "User"
  }'

2. Sign In (session is cached in Redis):
curl -X POST http://localhost:3000/auth/signin \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "admin123"
  }'

3. Access Web Dashboard (uses session cookie + Redis cache):
curl http://localhost:3000/web/dashboard \
  -H "Cookie: cnf.id=SESSION_ID"

4. Access API (uses JWT):
curl http://localhost:3000/api/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

5. Check Redis Cache:
redis-cli
> KEYS auth:sessions:*
> GET auth:sessions:SESSION_ID
*/

