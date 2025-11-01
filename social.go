package fiberauth

import (
	"fmt"

	"github.com/gofiber/fiber/v3"
	"github.com/izetmolla/fiberauth/social"
)

// GetProviders returns a list of available social provider names.
// This function retrieves all configured social providers and returns their names.
//
// Returns:
//   - []string: Array of provider names (e.g., ["google", "github"])
//   - error: Error if provider retrieval fails
//
// Example:
//
//	providers, err := auth.GetProviders()
//	if err != nil {
//	    // Handle error
//	}
//	// providers might be ["google", "github"]
func (q *Authorization) GetProviders() ([]string, error) {
	providers := social.GetProviders()
	providerNames := make([]string, 0, len(providers))
	for name := range providers {
		providerNames = append(providerNames, name)
	}
	return providerNames, nil
}

// GetProvider retrieves a specific social provider by name.
// Returns the provider instance if found, or an error if not found.
//
// Parameters:
//   - name: The name of the provider (e.g., "google", "github")
//
// Returns:
//   - social.Provider: The provider instance
//   - error: Error if provider is not found
//
// Example:
//
//	provider, err := auth.GetProvider("google")
//	if err != nil {
//	    // Handle error
//	}
//	// Use provider for OAuth operations
func (a *Authorization) GetProvider(name string) (social.Provider, error) {
	provider, exists := a.providers[name]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", name)
	}
	return provider, nil
}

// ProviderLogin initiates OAuth login with a social provider.
// Generates the authorization URL for the specified provider.
//
// Parameters:
//   - c: Fiber context containing the request
//   - providerName: The name of the social provider (e.g., "google", "github")
//
// Returns:
//   - string: The authorization URL for the provider
//   - error: Error if provider login initiation fails
//
// Example:
//
//	authURL, err := auth.ProviderLogin(c, "google")
//	if err != nil {
//	    // Handle error
//	}
//	// Redirect user to authURL
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
// Processes the callback, retrieves user information, and creates or finds the user.
//
// Parameters:
//   - c: Fiber context containing the callback request
//   - providerName: The name of the social provider (e.g., "google", "github")
//
// Returns:
//   - *AuthorizationResponse: Response containing tokens, session ID, and user data
//   - error: Error if callback processing fails
//
// Example:
//
//	response, err := auth.ProviderCallBack(c, "google")
//	if err != nil {
//	    // Handle error
//	}
//	// User is now authenticated and logged in
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
	sessionManager := NewSessionManager(a)
	if err := sessionManager.CreateAndStoreSession(foundUser, sessionID); err != nil {
		return nil, err
	}

	return sessionManager.CreateAuthorizationResponse(foundUser, tokens, sessionID), nil
}
