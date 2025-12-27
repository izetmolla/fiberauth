package main

import (
	"log"

	"github.com/gofiber/fiber/v3"
	"github.com/izetmolla/fiberauth"
)

// BasicAuthExample demonstrates basic authentication functionality
type BasicAuthExample struct {
	auth *fiberauth.Authorization
	app  *fiber.App
}

// NewBasicAuthExample creates a new basic authentication example
func NewBasicAuthExample() *BasicAuthExample {
	// Initialize authorization service
	config := &fiberauth.Config{
		JWTSecret: "your-super-secret-jwt-key-for-example",
		Debug:     true,
	}

	auth, err := fiberauth.New(config)
	if err != nil {
		log.Fatal("Failed to initialize authorization:", err)
	}

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c fiber.Ctx, err error) error {
			// Custom error handler for better error responses
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}

			return c.Status(code).JSON(fiber.Map{
				"error":   true,
				"message": err.Error(),
			})
		},
	})

	return &BasicAuthExample{
		auth: auth,
		app:  app,
	}
}

// setupRoutes configures the application routes
func (b *BasicAuthExample) setupRoutes() {
	// Health check endpoint
	b.app.Get("/health", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "ok",
			"service": "basic-auth-example",
		})
	})

	// Authentication routes
	auth := b.app.Group("/auth")
	auth.Post("/signup", b.handleSignUp)
	auth.Post("/signin", b.handleSignIn)
	auth.Post("/signout", b.handleSignOut)
	auth.Post("/refresh", b.handleRefreshToken)

	// Protected routes
	protected := b.app.Group("/protected")
	protected.Use(b.authMiddleware())
	protected.Get("/profile", b.handleGetProfile)
	protected.Get("/dashboard", b.handleDashboard)
}

// handleSignUp handles user registration
func (b *BasicAuthExample) handleSignUp(c fiber.Ctx) error {
	var req fiberauth.SignUpRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid request body",
		})
	}

	// Validate the request
	validator := fiberauth.NewValidator()
	if err := validator.ValidateRequired(req.FirstName, "first_name"); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": true, "field": "first_name", "message": err.Error()})
	}
	if err := validator.ValidateRequired(req.LastName, "last_name"); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": true, "field": "last_name", "message": err.Error()})
	}
	if err := validator.ValidateEmail(req.Email); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": true, "field": "email", "message": err.Error()})
	}
	if err := validator.ValidatePassword(req.Password); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": true, "field": "password", "message": err.Error()})
	}

	// Attempt to create the user
	response, errorFields := b.auth.SignUp(&req)
	if errorFields != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"field":   errorFields.Field,
			"message": errorFields.Error.Error(),
		})
	}

	// Set session cookie
	b.auth.SetSessionCookie(c, response.SessionID)

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"success": true,
		"message": "User created successfully",
		"data":    response,
	})
}

// handleSignIn handles user authentication
func (b *BasicAuthExample) handleSignIn(c fiber.Ctx) error {
	var req fiberauth.SignInRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid request body",
		})
	}

	// Validate the request
	validator := fiberauth.NewValidator()
	if err := validator.ValidateSignInEmailOrUsername(req.Email, req.Username); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": true, "field": "email", "message": err.Error()})
	}
	if err := validator.ValidatePassword(req.Password); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": true, "field": "password", "message": err.Error()})
	}

	// Attempt to authenticate the user
	response, errorFields := b.auth.SignIn(&req)
	if errorFields != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   true,
			"field":   errorFields.Field,
			"message": errorFields.Error.Error(),
		})
	}

	// Set session cookie
	b.auth.SetSessionCookie(c, response.SessionID)

	return c.JSON(fiber.Map{
		"success": true,
		"message": "User authenticated successfully",
		"data":    response,
	})
}

// handleSignOut handles user logout
func (b *BasicAuthExample) handleSignOut(c fiber.Ctx) error {
	var req fiberauth.SignOutRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid request body",
		})
	}

	response, errorFields := b.auth.SignOut(&req)
	if errorFields != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"field":   errorFields.Field,
			"message": errorFields.Error.Error(),
		})
	}

	// Clear session cookie
	c.ClearCookie("session") // Use a default cookie name

	return c.JSON(fiber.Map{
		"success": true,
		"message": "User signed out successfully",
		"data":    response,
	})
}

// handleRefreshToken handles token refresh
func (b *BasicAuthExample) handleRefreshToken(c fiber.Ctx) error {
	token, err := b.auth.HandleRefreshToken(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   true,
			"message": "Failed to refresh token: " + err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Token refreshed successfully",
		"data": fiber.Map{
			"access_token": token,
		},
	})
}

// handleGetProfile handles user profile retrieval
func (b *BasicAuthExample) handleGetProfile(c fiber.Ctx) error {
	// Get user from context (set by middleware)
	user := c.Locals("user")
	if user == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   true,
			"message": "User not authenticated",
		})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Profile retrieved successfully",
		"data":    user,
	})
}

// handleDashboard handles dashboard access
func (b *BasicAuthExample) handleDashboard(c fiber.Ctx) error {
	user := c.Locals("user")
	if user == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   true,
			"message": "User not authenticated",
		})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Welcome to your dashboard!",
		"data": fiber.Map{
			"user":      user,
			"dashboard": "This is your protected dashboard data",
		},
	})
}

// authMiddleware creates authentication middleware
func (b *BasicAuthExample) authMiddleware() fiber.Handler {
	return func(c fiber.Ctx) error {
		// Extract token from header
		token, err := b.auth.GetTokenFromHeader(c)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   true,
				"message": "No valid token provided",
			})
		}

		// Validate token
		claims, err := b.auth.ExtractToken(token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   true,
				"message": "Invalid or expired token",
			})
		}

		// Set user in context
		c.Locals("user", claims)
		return c.Next()
	}
}

// Run starts the example server
func (b *BasicAuthExample) Run(port string) error {
	b.setupRoutes()
	log.Printf("Starting basic auth example server on port %s", port)
	return b.app.Listen(":" + port)
}

func main() {
	example := NewBasicAuthExample()

	// Start the server
	if err := example.Run("8080"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
