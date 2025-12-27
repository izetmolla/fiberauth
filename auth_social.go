package fiberauth

import (
	"encoding/json"

	"github.com/gofiber/fiber/v3"
	"github.com/izetmolla/fiberauth/pkg/storage/models"
	"github.com/izetmolla/fiberauth/social"
)

// ProviderLogin initiates OAuth login with a social provider.
//
// Parameters:
//   - c: Fiber context containing the request
//   - providerName: The name of the social provider (e.g., "google", "github")
//
// Returns:
//   - string: The authorization URL for the provider
//   - error: Error if provider login initiation fails
func (a *Authorization) ProviderLogin(c fiber.Ctx, providerName string) (string, error) {
	// Retrieve the social provider instance
	providerInstance, err := a.GetProvider(providerName)
	if err != nil {
		return "", err
	}

	// Generate the authorization URL for the social provider
	authURL, err := a.social.GetAuthURL(c, providerInstance)
	if err != nil {
		return "", err
	}

	return authURL, nil
}

// ProviderCallBack handles the OAuth callback from a social provider.
//
// Parameters:
//   - c: Fiber context containing the callback request
//   - providerName: The name of the social provider (e.g., "google", "github")
//
// Returns:
//   - *AuthorizationResponse: Response containing tokens, session ID, and user data
//   - error: Error if callback processing fails
func (a *Authorization) ProviderCallBack(c fiber.Ctx, providerName string) (*AuthorizationResponse, error) {
	// Retrieve the social provider instance
	providerInstance, err := a.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	user, err := a.social.CompleteUserAuth(c, providerInstance, social.CompleteUserAuthOptions{
		ShouldLogout: true,
	})
	if err != nil {
		return nil, err
	}

	foundUser, err := a.findOrCreateUser(user.Email, &user)
	if err != nil {
		return nil, err
	}

	tokens, sessionID, err := a.authorize(foundUser, c.IP(), c.Get("User-Agent"), providerName)
	if err != nil {
		return nil, err
	}

	// Create and store session
	sessionData := &SessionData{
		ID:       sessionID,
		UserID:   foundUser.ID,
		Roles:    ensureJSONField(foundUser.Roles, "[]"),
		Metadata: ensureJSONField(foundUser.Metadata, "{}"),
		Options:  ensureJSONField(foundUser.Options, "{}"),
	}
	a.setRedisSession(sessionData)

	return &AuthorizationResponse{
		User:      userResponse(foundUser),
		SessionID: sessionID,
		Tokens:    *tokens,
	}, nil
}

// findOrCreateUser finds an existing user or creates a new one for social login.
func (a *Authorization) findOrCreateUser(email string, socialUser *social.User) (*models.User, error) {
	user, err := a.dbManager.FindUserByEmail(email, "")
	if err == nil {
		// User exists, return it
		return user, nil
	}

	// User doesn't exist, create new user
	return a.createUser(email, socialUser)
}

// createUser creates a new user from social authentication data.
func (a *Authorization) createUser(email string, socialUser *social.User) (*models.User, error) {
	user := &models.User{
		Email:     email,
		FirstName: socialUser.FirstName,
		LastName:  socialUser.LastName,
		AvatarURL: socialUser.AvatarURL,
		Roles:     json.RawMessage(`[]`),
		Metadata:  json.RawMessage(`{}`),
		Options:   json.RawMessage(`{}`),
	}

	if err := a.dbManager.CreateUser(user); err != nil {
		return nil, err
	}

	return user, nil
}

// ProvidersController returns the list of available social providers.
//
// Parameters:
//   - c: Fiber context containing the HTTP request
//
// Returns:
//   - error: Fiber error for HTTP response handling
func (a *Authorization) ProvidersController(c fiber.Ctx) error {
	providerNames := make([]string, 0, len(a.providers))
	for name := range a.providers {
		providerNames = append(providerNames, name)
	}
	return c.JSON(providerNames)
}

// ProviderLoginController handles the HTTP request for provider login.
//
// Parameters:
//   - c: Fiber context containing the HTTP request
//
// Returns:
//   - error: Fiber error for HTTP response handling
func (a *Authorization) ProviderLoginController(c fiber.Ctx) error {
	authURL, err := a.ProviderLogin(c, c.Params("provider"))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(a.ErrorJSON(err))
	}
	// Redirect the user to the social provider's authorization page
	return c.Redirect().To(authURL)
}

// ProviderCallBackController handles the HTTP callback from a social provider.
//
// Parameters:
//   - c: Fiber context containing the HTTP request
//
// Returns:
//   - error: Fiber error for HTTP response handling
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

