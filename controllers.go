package fiberauth

import (
	"encoding/json"
	"errors"

	"github.com/gofiber/fiber/v3"
)

// ControllerResponse represents a standardized response structure for controllers
type ControllerResponse struct {
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Field   string      `json:"field,omitempty"`
	Message string      `json:"message,omitempty"`
}

// handleErrorResponse creates a standardized error response for controllers
func (a *Authorization) handleErrorResponse(c fiber.Ctx, err error, statusCode int) error {
	if statusCode == 0 {
		statusCode = fiber.StatusInternalServerError
	}

	if errors.Is(err, ErrUnauthorized) {
		statusCode = fiber.StatusUnauthorized
	}

	return c.Status(statusCode).JSON(a.ErrorJSON(err))
}

// handleErrorFieldsResponse creates a standardized error response with field information
func (a *Authorization) handleErrorFieldsResponse(c fiber.Ctx, err *ErrorFields, statusCode int) error {
	if statusCode == 0 {
		statusCode = fiber.StatusOK
	}

	// Create error response with field information if available
	errorResponse := fiber.Map{
		"error": fiber.Map{
			"message": err.Error.Error(),
		},
	}

	// Add field information if available
	if err.Field != "" {
		errorResponse["error"].(fiber.Map)["field"] = err.Field
	}

	return c.Status(statusCode).JSON(errorResponse)
}

// handleSuccessResponse creates a standardized success response for controllers
func (a *Authorization) handleSuccessResponse(c fiber.Ctx, data interface{}) error {
	return c.JSON(data)
}

// bindAndValidateRequest binds the request body and validates it
func (a *Authorization) bindAndValidateRequest(c fiber.Ctx, request interface{}) error {
	if err := c.Bind().Body(request); err != nil {
		return err
	}
	return nil
}

// handleAuthorizationResponse handles the common pattern of authorization responses
func (a *Authorization) handleAuthorizationResponse(c fiber.Ctx, response *AuthorizationResponse, err *ErrorFields) error {
	if err != nil {
		return a.handleErrorFieldsResponse(c, err, fiber.StatusOK)
	}
	return a.handleSuccessResponse(c, response)
}

// =============================================================================
// CREDENTIAL CONTROLLERS
// =============================================================================

// SignInController handles the HTTP request for user sign-in.
// Binds the request body to SignInRequest and processes authentication.
//
// Parameters:
//   - c: Fiber context containing the HTTP request
//
// Returns:
//   - error: Fiber error for HTTP response handling
//
// Example:
//
//	app.Post("/signin", auth.SignInController)
func (a *Authorization) SignInController(c fiber.Ctx) error {
	request := new(SignInRequest)
	if err := a.bindAndValidateRequest(c, request); err != nil {
		return a.handleErrorResponse(c, err, fiber.StatusBadRequest)
	}

	res, err := a.SignIn(request)
	a.SetSessionCookie(c, res.SessionID)
	return a.handleAuthorizationResponse(c, res, err)
}

// SignUpController handles the HTTP request for user sign-up.
// Binds the request body to SignUpRequest and processes registration.
//
// Parameters:
//   - c: Fiber context containing the HTTP request
//
// Returns:
//   - error: Fiber error for HTTP response handling
//
// Example:
//
//	app.Post("/signup", auth.SignUpController)
func (a *Authorization) SignUpController(c fiber.Ctx) error {
	request := new(SignUpRequest)
	if err := a.bindAndValidateRequest(c, request); err != nil {
		return a.handleErrorResponse(c, err, fiber.StatusOK)
	}

	res, err := a.SignUp(request)
	a.SetSessionCookie(c, res.SessionID)
	return a.handleAuthorizationResponse(c, res, err)
}

// SignOutController handles the HTTP request for user sign-out.
// Processes the sign-out request and invalidates the user session.
//
// Parameters:
//   - c: Fiber context containing the HTTP request
//
// Returns:
//   - error: Fiber error for HTTP response handling
//
// Example:
//
//	app.Post("/signout", auth.SignOutController)
func (a *Authorization) SignOutController(c fiber.Ctx) error {
	// Extract token from request body or header
	request := new(SignOutRequest)
	if err := a.bindAndValidateRequest(c, request); err != nil {
		// If no body, try to get token from header
		if token := c.Get("Authorization"); token != "" {
			request.Token = token
		}
	}
	res, err := a.SignOut(request)
	if err != nil {
		return a.handleErrorFieldsResponse(c, err, fiber.StatusBadRequest)
	}

	a.RemoveSessionCookie(c)
	return a.handleSuccessResponse(c, res)
}

// HandleRefreshTokenController handles the HTTP request for token refresh.
// Extracts the refresh token from the request and generates a new access token.
//
// Parameters:
//   - c: Fiber context containing the HTTP request
//
// Returns:
//   - error: Fiber error for HTTP response handling
//
// Example:
//
//	app.Post("/refresh", auth.HandleRefreshTokenController)
func (a *Authorization) HandleRefreshTokenController(c fiber.Ctx) error {
	if c.Get(RefreshTokenHandlerIdentifier, "no") == "no" {
		return c.Next()
	}

	accessToken, err := a.HandleRefreshToken(c)
	if err != nil {
		return a.handleErrorResponse(c, err, fiber.StatusUnauthorized)
	}

	return c.Status(fiber.StatusOK).JSON(accessToken)
}

// =============================================================================
// SOCIAL CONTROLLERS
// =============================================================================

// ProvidersController returns the list of available social providers.
// Handles the HTTP request to get all configured social providers.
//
// Parameters:
//   - c: Fiber context containing the HTTP request
//
// Returns:
//   - error: Fiber error for HTTP response handling
//
// Example:
//
//	app.Get("/providers", auth.ProvidersController)
func (a *Authorization) ProvidersController(c fiber.Ctx) error {
	providers, err := a.GetProviders()
	if err != nil {
		return a.handleErrorResponse(c, err, fiber.StatusInternalServerError)
	}
	return a.handleSuccessResponse(c, providers)
}

// ProviderLoginController handles the HTTP request for provider login.
// Initiates OAuth login with the specified social provider.
//
// Parameters:
//   - c: Fiber context containing the HTTP request
//
// Returns:
//   - error: Fiber error for HTTP response handling
//
// Example:
//
//	app.Get("/login/:provider", auth.ProviderLoginController)
func (a *Authorization) ProviderLoginController(c fiber.Ctx) error {
	authURL, err := a.ProviderLogin(c, c.Params("provider"))
	if err != nil {
		return a.handleErrorResponse(c, err, fiber.StatusInternalServerError)
	}
	// Redirect the user to the social provider's authorization page
	return c.Redirect().To(authURL)
}

// ProviderCallBackController handles the HTTP callback from a social provider.
// Processes the OAuth callback and completes the authentication flow.
//
// Parameters:
//   - c: Fiber context containing the HTTP request
//
// Returns:
//   - error: Fiber error for HTTP response handling
//
// Example:
//
//	app.Get("/callback/:provider", auth.ProviderCallBackController)
func (a *Authorization) ProviderCallBackController(c fiber.Ctx) error {
	c.Set("Content-Type", "text/html")
	res, err := a.ProviderCallBack(c, c.Params("provider"))
	if err != nil {
		return c.SendString(a.RenderRedirectHTML(fiber.Map{
			"jsData": a.JSONErrorString(err),
		}))
	}

	jsonData, _ := json.Marshal(res)
	a.SetSessionCookie(c, res.SessionID)
	return c.SendString(a.RenderRedirectHTML(fiber.Map{
		"jsData": string(jsonData),
	}))
}
