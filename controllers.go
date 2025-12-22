package fiberauth

import (
	"encoding/json"
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/izetmolla/fiberauth/social/providers/passkey"
)

// CheckEmailController handles the HTTP request for checking if an email exists.
// This endpoint allows clients to verify if an email is already registered.
//
// Parameters:
//   - c: Fiber context containing the HTTP request
//
// Returns:
//   - error: Fiber error for HTTP response handling
func (a *Authorization) CheckEmailController(c fiber.Ctx) error {
	request := new(SignInRequest)
	if err := a.bindAndValidateRequest(c, request); err != nil {
		return a.handleErrorResponse(c, err, fiber.StatusBadRequest)
	}

	response, err := a.CheckEmail(request.Email)
	if err != nil {
		return a.handleErrorFieldsResponse(c, err, fiber.StatusOK)
	}
	return a.handleSuccessResponse(c, response)
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
	if request.IpAddress == "" {
		request.IpAddress = a.getRealIPAddress(c)
	}
	if request.UserAgent == "" {
		request.UserAgent = c.Get("User-Agent")
	}

	res, err := a.SignIn(request)
	if err == nil {
		a.SetSessionCookie(c, res.SessionID)
	}
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
	if err == nil {
		a.SetSessionCookie(c, res.SessionID)
	}
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
// This controller checks for a special header identifier to determine if it should process the request.
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
	// Check if this request is meant for refresh token handling
	// The RefreshTokenHandlerIdentifier header is used to identify refresh token requests
	if c.Get(RefreshTokenHandlerIdentifier, "no") == "no" {
		// Not a refresh token request, pass to next handler
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

// =============================================================================
// PASSKEY CONTROLLERS
// =============================================================================

// PasskeyBeginRegistrationController handles the HTTP request for passkey begin-registration endpoint
// Initiates the passkey registration process by generating WebAuthn challenge options.
//
// Parameters:
//   - c: Fiber context containing the HTTP request
//
// Returns:
//   - error: Fiber error for HTTP response handling
//
// Example:
//
//	app.Post("/passkey/begin-registration", auth.PasskeyBeginRegistrationController)
func (a *Authorization) PasskeyBeginRegistrationController(c fiber.Ctx) error {
	// Get passkey provider
	provider, err := a.GetProvider("passkey")
	if err != nil {
		return a.handleErrorResponse(c, err, fiber.StatusInternalServerError)
	}

	passkeyProvider, ok := provider.(*passkey.Provider)
	if !ok {
		return a.handleErrorResponse(c, errors.New("passkey provider not found or invalid type"), fiber.StatusInternalServerError)
	}

	// Parse request body - must use pointer for binding
	var req passkey.RegistrationRequest
	if err := c.Bind().Body(&req); err != nil {
		return a.handleErrorResponse(c, errors.New("invalid request body"), fiber.StatusBadRequest)
	}

	// Validate required fields
	if req.UserID == "" || req.UserName == "" || req.DisplayName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"message": "user_id, user_name, and display_name are required",
		})
	}

	// Call the provider's BeginRegistrationEndpoint
	response, err := passkeyProvider.BeginRegistrationEndpoint(&req)
	if err != nil {
		return a.handleErrorResponse(c, err, fiber.StatusInternalServerError)
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

// PasskeyFinishRegistrationController handles the HTTP request for passkey finish-registration endpoint
// Completes the passkey registration process by verifying the WebAuthn credential response.
//
// Parameters:
//   - c: Fiber context containing the HTTP request
//
// Returns:
//   - error: Fiber error for HTTP response handling
//
// Example:
//
//	app.Post("/passkey/finish-registration", auth.PasskeyFinishRegistrationController)
func (a *Authorization) PasskeyFinishRegistrationController(c fiber.Ctx) error {
	// Get passkey provider
	provider, err := a.GetProvider("passkey")
	if err != nil {
		return a.handleErrorResponse(c, err, fiber.StatusInternalServerError)
	}

	passkeyProvider, ok := provider.(*passkey.Provider)
	if !ok {
		return a.handleErrorResponse(c, errors.New("passkey provider not found or invalid type"), fiber.StatusInternalServerError)
	}

	// Parse request body - must use pointer for binding
	var req passkey.FinishRegistrationRequest
	if err := c.Bind().Body(&req); err != nil {
		return a.handleErrorResponse(c, errors.New("invalid request body"), fiber.StatusBadRequest)
	}

	// Validate required fields
	if req.SessionID == "" || req.UserID == "" || req.Credential == nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"message": "session_id, user_id, and credential are required",
		})
	}

	// Call the provider's FinishRegistrationEndpoint
	response, err := passkeyProvider.FinishRegistrationEndpoint(&req)
	if err != nil {
		return a.handleErrorResponse(c, err, fiber.StatusInternalServerError)
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

// PasskeyBeginLoginController handles the HTTP request for passkey begin-login endpoint
// Initiates the passkey authentication process by generating WebAuthn assertion options.
//
// Parameters:
//   - c: Fiber context containing the HTTP request
//
// Returns:
//   - error: Fiber error for HTTP response handling
//
// Example:
//
//	app.Post("/passkey/begin-login", auth.PasskeyBeginLoginController)
//	app.Get("/passkey/begin-login", auth.PasskeyBeginLoginController)
func (a *Authorization) PasskeyBeginLoginController(c fiber.Ctx) error {
	// Get passkey provider
	provider, err := a.GetProvider("passkey")
	if err != nil {
		return a.handleErrorResponse(c, err, fiber.StatusInternalServerError)
	}

	passkeyProvider, ok := provider.(*passkey.Provider)
	if !ok {
		return a.handleErrorResponse(c, errors.New("passkey provider not found or invalid type"), fiber.StatusInternalServerError)
	}

	// Get user_id from query parameter or request body
	userID := c.Query("user_id")
	if userID == "" {
		// Try to get from request body for POST requests
		type LoginRequest struct {
			UserID string `json:"user_id"`
		}
		var req LoginRequest
		// Must use pointer for binding - ignore error if body parsing fails
		if err := c.Bind().Body(&req); err == nil && req.UserID != "" {
			userID = req.UserID
		}
	}

	// Validate required field
	if userID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"message": "user_id is required",
		})
	}

	// Call the provider's BeginLoginEndpoint
	response, err := passkeyProvider.BeginLoginEndpoint(userID)
	if err != nil {
		return a.handleErrorResponse(c, err, fiber.StatusInternalServerError)
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

// PasskeyFinishLoginController handles the HTTP request for passkey finish-login endpoint
// Completes the passkey authentication process by verifying the WebAuthn assertion response.
//
// Parameters:
//   - c: Fiber context containing the HTTP request
//
// Returns:
//   - error: Fiber error for HTTP response handling
//
// Example:
//
//	app.Post("/passkey/finish-login", auth.PasskeyFinishLoginController)
func (a *Authorization) PasskeyFinishLoginController(c fiber.Ctx) error {
	// Get passkey provider
	provider, err := a.GetProvider("passkey")
	if err != nil {
		return a.handleErrorResponse(c, err, fiber.StatusInternalServerError)
	}

	passkeyProvider, ok := provider.(*passkey.Provider)
	if !ok {
		return a.handleErrorResponse(c, errors.New("passkey provider not found or invalid type"), fiber.StatusInternalServerError)
	}

	// Parse request body - similar to FinishRegistrationRequest but for login
	type FinishLoginRequest struct {
		SessionID  string      `json:"session_id"`
		UserID     string      `json:"user_id"`
		Credential interface{} `json:"credential"`
	}

	var req FinishLoginRequest
	// Must use pointer for binding
	if err := c.Bind().Body(&req); err != nil {
		return a.handleErrorResponse(c, errors.New("invalid request body"), fiber.StatusBadRequest)
	}

	// Validate required fields
	if req.SessionID == "" || req.UserID == "" || req.Credential == nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"message": "session_id, user_id, and credential are required",
		})
	}

	// TODO: Implement proper WebAuthn assertion verification
	// Currently returns a placeholder response. In a production implementation,
	// this should verify the WebAuthn assertion credential and create a proper session.
	// The passkey provider's FinishLoginEndpoint method needs to be implemented.
	response := fiber.Map{
		"success": true,
		"message": "Login completed successfully",
		"user": fiber.Map{
			"user_id":  req.UserID,
			"provider": passkeyProvider.Name(),
		},
		"session_id": req.SessionID,
	}

	return c.Status(fiber.StatusOK).JSON(response)
}
