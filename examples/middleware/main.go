package main

import (
	"log"

	"github.com/gofiber/fiber/v3"
	"github.com/izetmolla/fiberauth"
)

// MiddlewareExample demonstrates middleware usage for authentication and authorization
type MiddlewareExample struct {
	auth *fiberauth.Authorization
	app  *fiber.App
}

// NewMiddlewareExample creates a new middleware example
func NewMiddlewareExample() *MiddlewareExample {
	// Initialize authorization service
	config := &fiberauth.Config{
		JWTSecret: "your-super-secret-jwt-key-for-middleware-example",
		Debug:     true,
	}

	auth, err := fiberauth.New(config)
	if err != nil {
		log.Fatal("Failed to initialize authorization:", err)
	}

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c fiber.Ctx, err error) error {
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

	return &MiddlewareExample{
		auth: auth,
		app:  app,
	}
}

// setupRoutes configures the application routes with middleware
func (m *MiddlewareExample) setupRoutes() {
	// Health check endpoint (no middleware)
	m.app.Get("/health", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "ok",
			"service": "middleware-example",
		})
	})

	// Public routes (no authentication required)
	public := m.app.Group("/public")
	public.Get("/info", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "This is public information",
			"access":  "No authentication required",
		})
	})

	// Protected routes (authentication required)
	protected := m.app.Group("/protected")
	protected.Use(m.jwtMiddleware())
	protected.Get("/profile", m.handleGetProfile)
	protected.Get("/settings", m.handleGetSettings)

	// Admin routes (authentication + admin role required)
	admin := m.app.Group("/admin")
	admin.Use(m.jwtMiddleware())
	admin.Use(m.roleMiddleware([]string{"admin"}))
	admin.Get("/dashboard", m.handleAdminDashboard)
	admin.Get("/users", m.handleGetUsers)
	admin.Post("/users", m.handleCreateUser)

	// Moderator routes (authentication + moderator role required)
	moderator := m.app.Group("/moderator")
	moderator.Use(m.jwtMiddleware())
	moderator.Use(m.roleMiddleware([]string{"moderator", "admin"}))
	moderator.Get("/content", m.handleGetContent)
	moderator.Post("/content/approve", m.handleApproveContent)

	// Custom middleware example
	custom := m.app.Group("/custom")
	custom.Use(m.customMiddleware())
	custom.Get("/data", m.handleCustomData)
}

// jwtMiddleware creates JWT authentication middleware
func (m *MiddlewareExample) jwtMiddleware() fiber.Handler {
	return func(c fiber.Ctx) error {
		// Extract token from header
		token, err := m.auth.GetTokenFromHeader(c)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   true,
				"message": "No valid token provided",
			})
		}

		// Validate token
		claims, err := m.auth.ExtractToken(token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   true,
				"message": "Invalid or expired token",
			})
		}

		// Set user information in context
		c.Locals("user_id", claims.UserID)
		c.Locals("session_id", claims.SessionID)
		c.Locals("claims", claims)

		return c.Next()
	}
}

// roleMiddleware creates role-based access control middleware
func (m *MiddlewareExample) roleMiddleware(requiredRoles []string) fiber.Handler {
	return func(c fiber.Ctx) error {
		// Get user information from context
		userID := c.Locals("user_id")
		if userID == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   true,
				"message": "User not authenticated",
			})
		}

		// In a real application, you would fetch user roles from the database
		// For this example, we'll use a simple role mapping
		userRoles := m.getUserRoles(userID.(string))

		// Check if user has required roles
		if !m.checkUserRoles(requiredRoles, userRoles) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":          true,
				"message":        "Insufficient permissions",
				"required_roles": requiredRoles,
				"user_roles":     userRoles,
			})
		}

		// Set roles in context for downstream handlers
		c.Locals("user_roles", userRoles)
		c.Locals("required_roles", requiredRoles)

		return c.Next()
	}
}

// checkUserRoles checks if user has any of the required roles
func (m *MiddlewareExample) checkUserRoles(requiredRoles []string, userRoles []string) bool {
	// If no roles are required, allow access
	if len(requiredRoles) == 0 {
		return true
	}

	// Check if user has any of the required roles
	for _, requiredRole := range requiredRoles {
		for _, userRole := range userRoles {
			if requiredRole == userRole {
				return true
			}
		}
	}

	return false
}

// customMiddleware demonstrates custom middleware functionality
func (m *MiddlewareExample) customMiddleware() fiber.Handler {
	return func(c fiber.Ctx) error {
		// Add custom headers
		c.Set("X-Custom-Middleware", "enabled")
		c.Set("X-Request-ID", c.Get("X-Request-ID", "default-id"))

		// Log request information
		log.Printf("Custom middleware: %s %s", c.Method(), c.Path())

		// Add custom data to context
		c.Locals("custom_data", fiber.Map{
			"middleware": "custom",
			"timestamp":  "2024-01-01T00:00:00Z",
		})

		return c.Next()
	}
}

// getUserRoles returns user roles (simplified for example)
func (m *MiddlewareExample) getUserRoles(userID string) []string {
	// In a real application, this would fetch from database
	roleMap := map[string][]string{
		"user-1": {"user"},
		"user-2": {"user", "moderator"},
		"user-3": {"user", "admin"},
		"user-4": {"user", "moderator", "admin"},
	}

	if roles, exists := roleMap[userID]; exists {
		return roles
	}
	return []string{"user"} // Default role
}

// handleGetProfile handles user profile retrieval
func (m *MiddlewareExample) handleGetProfile(c fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	sessionID := c.Locals("session_id").(string)

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Profile retrieved successfully",
		"data": fiber.Map{
			"user_id":    userID,
			"session_id": sessionID,
			"profile": fiber.Map{
				"name":  "John Doe",
				"email": "john@example.com",
				"roles": m.getUserRoles(userID),
			},
		},
	})
}

// handleGetSettings handles user settings retrieval
func (m *MiddlewareExample) handleGetSettings(c fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Settings retrieved successfully",
		"data": fiber.Map{
			"user_id": userID,
			"settings": fiber.Map{
				"theme":         "dark",
				"language":      "en",
				"timezone":      "UTC",
				"notifications": true,
			},
		},
	})
}

// handleAdminDashboard handles admin dashboard access
func (m *MiddlewareExample) handleAdminDashboard(c fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	userRoles := c.Locals("user_roles").([]string)

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Admin dashboard accessed successfully",
		"data": fiber.Map{
			"user_id":    userID,
			"user_roles": userRoles,
			"dashboard": fiber.Map{
				"total_users":     1000,
				"active_sessions": 150,
				"system_status":   "healthy",
				"recent_activity": []string{
					"User registration: 5 minutes ago",
					"System backup: 1 hour ago",
					"Security scan: 2 hours ago",
				},
			},
		},
	})
}

// handleGetUsers handles user list retrieval (admin only)
func (m *MiddlewareExample) handleGetUsers(c fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Users retrieved successfully",
		"data": fiber.Map{
			"requested_by": userID,
			"users": []fiber.Map{
				{"id": "user-1", "name": "John Doe", "email": "john@example.com", "role": "user"},
				{"id": "user-2", "name": "Jane Smith", "email": "jane@example.com", "role": "moderator"},
				{"id": "user-3", "name": "Admin User", "email": "admin@example.com", "role": "admin"},
			},
		},
	})
}

// handleCreateUser handles user creation (admin only)
func (m *MiddlewareExample) handleCreateUser(c fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	var req struct {
		Name  string `json:"name"`
		Email string `json:"email"`
		Role  string `json:"role"`
	}

	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid request body",
		})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "User created successfully",
		"data": fiber.Map{
			"created_by": userID,
			"user": fiber.Map{
				"id":    "new-user-id",
				"name":  req.Name,
				"email": req.Email,
				"role":  req.Role,
			},
		},
	})
}

// handleGetContent handles content retrieval (moderator only)
func (m *MiddlewareExample) handleGetContent(c fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	userRoles := c.Locals("user_roles").([]string)

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Content retrieved successfully",
		"data": fiber.Map{
			"requested_by": userID,
			"user_roles":   userRoles,
			"content": []fiber.Map{
				{"id": "content-1", "title": "Article 1", "status": "pending"},
				{"id": "content-2", "title": "Article 2", "status": "approved"},
				{"id": "content-3", "title": "Article 3", "status": "rejected"},
			},
		},
	})
}

// handleApproveContent handles content approval (moderator only)
func (m *MiddlewareExample) handleApproveContent(c fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	var req struct {
		ContentID string `json:"content_id"`
		Action    string `json:"action"` // "approve" or "reject"
	}

	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid request body",
		})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Content action completed successfully",
		"data": fiber.Map{
			"actioned_by": userID,
			"content_id":  req.ContentID,
			"action":      req.Action,
			"status":      "completed",
		},
	})
}

// handleCustomData handles custom middleware data
func (m *MiddlewareExample) handleCustomData(c fiber.Ctx) error {
	customData := c.Locals("custom_data").(fiber.Map)
	requestID := c.Get("X-Request-ID", "default-id")

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Custom data retrieved successfully",
		"data": fiber.Map{
			"custom_data": customData,
			"request_id":  requestID,
			"headers": fiber.Map{
				"custom_middleware": c.Get("X-Custom-Middleware"),
			},
		},
	})
}

// Run starts the example server
func (m *MiddlewareExample) Run(port string) error {
	m.setupRoutes()
	log.Printf("Starting middleware example server on port %s", port)
	return m.app.Listen(":" + port)
}

func main() {
	example := NewMiddlewareExample()

	// Start the server
	if err := example.Run("8081"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
