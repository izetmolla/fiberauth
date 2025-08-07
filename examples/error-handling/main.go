package main

import (
	"errors"
	"log"

	"github.com/gofiber/fiber/v3"
	"github.com/izetmolla/fiberauth"
)

// ErrorHandlingExample demonstrates comprehensive error handling patterns
type ErrorHandlingExample struct {
	auth *fiberauth.Authorization
	app  *fiber.App
}

// NewErrorHandlingExample creates a new error handling example
func NewErrorHandlingExample() *ErrorHandlingExample {
	// Initialize authorization service
	config := &fiberauth.Config{
		JWTSecret: "your-super-secret-jwt-key-for-error-handling-example",
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

	return &ErrorHandlingExample{
		auth: auth,
		app:  app,
	}
}

// setupRoutes configures the application routes
func (e *ErrorHandlingExample) setupRoutes() {
	// Health check endpoint
	e.app.Get("/health", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "ok",
			"service": "error-handling-example",
		})
	})

	// Error demonstration routes
	errors := e.app.Group("/errors")
	errors.Get("/validation", e.handleValidationError)
	errors.Get("/authentication", e.handleAuthenticationError)
	errors.Get("/authorization", e.handleAuthorizationError)
	errors.Get("/database", e.handleDatabaseError)
	errors.Get("/custom", e.handleCustomError)
	errors.Post("/test-validation", e.handleTestValidation)

	// Error recovery demonstration
	recovery := e.app.Group("/recovery")
	recovery.Get("/panic", e.handlePanic)
	recovery.Get("/timeout", e.handleTimeout)
	recovery.Get("/resource", e.handleResourceError)
}

// handleValidationError demonstrates validation error handling
func (e *ErrorHandlingExample) handleValidationError(c fiber.Ctx) error {
	// Simulate validation errors
	validationErrors := []*fiberauth.ErrorFields{
		{
			Error: errors.New("email is required"),
			Field: "email",
		},
		{
			Error: errors.New("password must be at least 6 characters"),
			Field: "password",
		},
		{
			Error: errors.New("first name is required"),
			Field: "first_name",
		},
	}

	// Return multiple validation errors
	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
		"error":   true,
		"message": "Validation failed",
		"errors":  validationErrors,
	})
}

// handleAuthenticationError demonstrates authentication error handling
func (e *ErrorHandlingExample) handleAuthenticationError(c fiber.Ctx) error {
	// Simulate authentication errors
	authError := &fiberauth.ErrorFields{
		Error: fiberauth.ErrInvalidCredentials,
		Field: "password",
	}

	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"error":   true,
		"message": "Authentication failed",
		"field":   authError.Field,
		"details": authError.Error.Error(),
	})
}

// handleAuthorizationError demonstrates authorization error handling
func (e *ErrorHandlingExample) handleAuthorizationError(c fiber.Ctx) error {
	// Simulate authorization errors
	return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
		"error":          true,
		"message":        "Insufficient permissions",
		"required_roles": []string{"admin"},
		"user_roles":     []string{"user"},
		"details":        "User does not have required admin role",
	})
}

// handleDatabaseError demonstrates database error handling
func (e *ErrorHandlingExample) handleDatabaseError(c fiber.Ctx) error {
	// Simulate database errors
	dbError := errors.New("connection to database failed")

	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
		"error":   true,
		"message": "Database error occurred",
		"details": dbError.Error(),
		"code":    "DB_CONNECTION_FAILED",
	})
}

// handleCustomError demonstrates custom error handling
func (e *ErrorHandlingExample) handleCustomError(c fiber.Ctx) error {
	// Simulate custom business logic errors
	customError := &CustomBusinessError{
		Code:    "BUSINESS_RULE_VIOLATION",
		Message: "User quota exceeded",
		Details: "User has exceeded their monthly quota of 1000 requests",
	}

	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
		"error":   true,
		"code":    customError.Code,
		"message": customError.Message,
		"details": customError.Details,
	})
}

// handleTestValidation demonstrates validation testing
func (e *ErrorHandlingExample) handleTestValidation(c fiber.Ctx) error {
	var req struct {
		Email     string `json:"email"`
		Password  string `json:"password"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}

	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid JSON format",
		})
	}

	// Validate the request
	validator := fiberauth.NewValidator()
	var validationErrors []*fiberauth.ErrorFields

	// Validate email
	if err := validator.ValidateEmail(req.Email); err != nil {
		if validationError, ok := err.(*fiberauth.ValidationError); ok {
			validationErrors = append(validationErrors, &fiberauth.ErrorFields{
				Error: validationError,
				Field: "email",
			})
		}
	}

	// Validate password
	if err := validator.ValidatePassword(req.Password); err != nil {
		if validationError, ok := err.(*fiberauth.ValidationError); ok {
			validationErrors = append(validationErrors, &fiberauth.ErrorFields{
				Error: validationError,
				Field: "password",
			})
		}
	}

	// Validate first name
	if err := validator.ValidateRequired(req.FirstName, "first_name"); err != nil {
		if validationError, ok := err.(*fiberauth.ValidationError); ok {
			validationErrors = append(validationErrors, &fiberauth.ErrorFields{
				Error: validationError,
				Field: "first_name",
			})
		}
	}

	// Validate last name
	if err := validator.ValidateRequired(req.LastName, "last_name"); err != nil {
		if validationError, ok := err.(*fiberauth.ValidationError); ok {
			validationErrors = append(validationErrors, &fiberauth.ErrorFields{
				Error: validationError,
				Field: "last_name",
			})
		}
	}

	if len(validationErrors) > 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": "Validation failed",
			"errors":  validationErrors,
		})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Validation passed",
		"data":    req,
	})
}

// handlePanic demonstrates panic recovery
func (e *ErrorHandlingExample) handlePanic(c fiber.Ctx) error {
	// Simulate a panic
	panic("This is a simulated panic for demonstration purposes")
}

// handleTimeout demonstrates timeout error handling
func (e *ErrorHandlingExample) handleTimeout(c fiber.Ctx) error {
	// Simulate a timeout error
	timeoutError := errors.New("request timeout after 30 seconds")

	return c.Status(fiber.StatusRequestTimeout).JSON(fiber.Map{
		"error":   true,
		"message": "Request timeout",
		"details": timeoutError.Error(),
		"code":    "REQUEST_TIMEOUT",
	})
}

// handleResourceError demonstrates resource error handling
func (e *ErrorHandlingExample) handleResourceError(c fiber.Ctx) error {
	// Simulate a resource error
	resourceError := errors.New("insufficient memory to process request")

	return c.Status(fiber.StatusInsufficientStorage).JSON(fiber.Map{
		"error":   true,
		"message": "Resource error",
		"details": resourceError.Error(),
		"code":    "INSUFFICIENT_RESOURCES",
	})
}

// CustomBusinessError represents a custom business logic error
type CustomBusinessError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details"`
}

func (e *CustomBusinessError) Error() string {
	return e.Message
}

// Run starts the example server
func (e *ErrorHandlingExample) Run(port string) error {
	e.setupRoutes()
	log.Printf("Starting error handling example server on port %s", port)
	return e.app.Listen(":" + port)
}

func main() {
	example := NewErrorHandlingExample()

	// Start the server
	if err := example.Run("8082"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
