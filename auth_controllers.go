package fiberauth

import (
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/izetmolla/fiberauth/social/providers/passkey"
)

// SignInController handles the HTTP request for user sign-in.
func (a *Authorization) SignInController(c fiber.Ctx) error {
	request := new(SignInRequest)
	if err := c.Bind().Body(request); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(a.ErrorJSON(err))
	}
	
	if request.IpAddress == "" {
		request.IpAddress = getRealIPAddress(c)
	}
	if request.UserAgent == "" {
		request.UserAgent = c.Get("User-Agent")
	}

	res, err := a.SignIn(request)
	if err != nil {
		return handleErrorFieldsResponse(c, err, fiber.StatusOK)
	}
	
	a.SetSessionCookie(c, res.SessionID)
	return c.JSON(res)
}

// SignUpController handles the HTTP request for user sign-up.
func (a *Authorization) SignUpController(c fiber.Ctx) error {
	request := new(SignUpRequest)
	if err := c.Bind().Body(request); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(a.ErrorJSON(err))
	}

	res, err := a.SignUp(request)
	if err != nil {
		return handleErrorFieldsResponse(c, err, fiber.StatusOK)
	}
	
	a.SetSessionCookie(c, res.SessionID)
	return c.JSON(res)
}

// SignOutController handles the HTTP request for user sign-out.
func (a *Authorization) SignOutController(c fiber.Ctx) error {
	request := new(SignOutRequest)
	if err := c.Bind().Body(request); err != nil {
		// If no body, try to get token from header
		if token := c.Get("Authorization"); token != "" {
			request.Token = token
		}
	}
	
	res, err := a.SignOut(request)
	if err != nil {
		return handleErrorFieldsResponse(c, err, fiber.StatusBadRequest)
	}
	
	a.RemoveSessionCookie(c)
	return c.JSON(res)
}

// HandleRefreshTokenController handles the HTTP request for token refresh.
func (a *Authorization) HandleRefreshTokenController(c fiber.Ctx) error {
	// Check if this request is meant for refresh token handling
	if c.Get(RefreshTokenHandlerIdentifier, "no") == "no" {
		return c.Next()
	}

	accessToken, err := a.HandleRefreshToken(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(a.ErrorJSON(err))
	}

	return c.Status(fiber.StatusOK).JSON(accessToken)
}

// CheckEmailController handles the HTTP request for checking if an email exists.
func (a *Authorization) CheckEmailController(c fiber.Ctx) error {
	request := new(SignInRequest)
	if err := c.Bind().Body(request); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(a.ErrorJSON(err))
	}

	response, err := a.CheckEmail(request.Email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(a.ErrorJSON(err))
	}
	return c.JSON(response)
}

// PasskeyBeginRegistrationController handles passkey registration initiation.
func (a *Authorization) PasskeyBeginRegistrationController(c fiber.Ctx) error {
	provider, err := a.GetProvider("passkey")
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(a.ErrorJSON(err))
	}

	passkeyProvider, ok := provider.(*passkey.Provider)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(a.ErrorJSON(errors.New("passkey provider not found")))
	}

	var req passkey.RegistrationRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(a.ErrorJSON(errors.New("invalid request body")))
	}

	if req.UserID == "" || req.UserName == "" || req.DisplayName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"message": "user_id, user_name, and display_name are required",
		})
	}

	response, err := passkeyProvider.BeginRegistrationEndpoint(&req)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(a.ErrorJSON(err))
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

// PasskeyFinishRegistrationController handles passkey registration completion.
func (a *Authorization) PasskeyFinishRegistrationController(c fiber.Ctx) error {
	provider, err := a.GetProvider("passkey")
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(a.ErrorJSON(err))
	}

	passkeyProvider, ok := provider.(*passkey.Provider)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(a.ErrorJSON(errors.New("passkey provider not found")))
	}

	var req passkey.FinishRegistrationRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(a.ErrorJSON(errors.New("invalid request body")))
	}

	if req.SessionID == "" || req.UserID == "" || req.Credential == nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"message": "session_id, user_id, and credential are required",
		})
	}

	response, err := passkeyProvider.FinishRegistrationEndpoint(&req)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(a.ErrorJSON(err))
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

// PasskeyBeginLoginController handles passkey authentication initiation.
func (a *Authorization) PasskeyBeginLoginController(c fiber.Ctx) error {
	provider, err := a.GetProvider("passkey")
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(a.ErrorJSON(err))
	}

	passkeyProvider, ok := provider.(*passkey.Provider)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(a.ErrorJSON(errors.New("passkey provider not found")))
	}

	userID := c.Query("user_id")
	if userID == "" {
		type LoginRequest struct {
			UserID string `json:"user_id"`
		}
		var req LoginRequest
		if err := c.Bind().Body(&req); err == nil && req.UserID != "" {
			userID = req.UserID
		}
	}

	if userID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"message": "user_id is required",
		})
	}

	response, err := passkeyProvider.BeginLoginEndpoint(userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(a.ErrorJSON(err))
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

// PasskeyFinishLoginController handles passkey authentication completion.
func (a *Authorization) PasskeyFinishLoginController(c fiber.Ctx) error {
	provider, err := a.GetProvider("passkey")
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(a.ErrorJSON(err))
	}

	passkeyProvider, ok := provider.(*passkey.Provider)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(a.ErrorJSON(errors.New("passkey provider not found")))
	}

	type FinishLoginRequest struct {
		SessionID  string      `json:"session_id"`
		UserID     string      `json:"user_id"`
		Credential interface{} `json:"credential"`
	}

	var req FinishLoginRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(a.ErrorJSON(errors.New("invalid request body")))
	}

	if req.SessionID == "" || req.UserID == "" || req.Credential == nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"message": "session_id, user_id, and credential are required",
		})
	}

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

// Helper functions

func handleErrorFieldsResponse(c fiber.Ctx, err *ErrorFields, statusCode int) error {
	if statusCode == 0 {
		statusCode = fiber.StatusOK
	}

	errorResponse := fiber.Map{
		"error": fiber.Map{
			"message": err.Error.Error(),
		},
	}

	if err.Field != "" {
		errorResponse["error"].(fiber.Map)["field"] = err.Field
	}

	return c.Status(statusCode).JSON(errorResponse)
}

func getRealIPAddress(c fiber.Ctx) string {
	// Check for Cloudflare's CF-Connecting-IP header first
	if cfIP := c.Get("CF-Connecting-IP"); cfIP != "" {
		return cfIP
	}

	// Check for X-Real-IP header
	if realIP := c.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	// Check for X-Forwarded-For header
	if forwardedFor := c.Get("X-Forwarded-For"); forwardedFor != "" {
		// X-Forwarded-For can contain multiple IPs
		for idx := 0; idx < len(forwardedFor); idx++ {
			if forwardedFor[idx] == ',' {
				return forwardedFor[:idx]
			}
		}
		return forwardedFor
	}

	// Fallback to direct connection IP
	return c.IP()
}

