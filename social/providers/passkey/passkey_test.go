package passkey_test

import (
	"testing"

	"github.com/izetmolla/fiberauth/social"
	"github.com/izetmolla/fiberauth/social/providers/passkey"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()
	a.Equal(provider.Name(), "passkey")
	a.Equal("/callback", provider.CallbackURL)
	a.Equal("localhost", provider.RelyingParty)
	a.Equal("http://localhost:3000", provider.Origin)
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()
	a.Implements((*social.Provider)(nil), provider)
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()

	session, err := provider.BeginAuth("test_state")
	a.NoError(err)

	s := session.(*passkey.Session)
	a.Equal("test_state", s.UserID)
	a.Equal("test_state_challenge", s.Challenge)
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()

	sessionJSON := `{"challenge":"test_challenge","user_id":"test_user","user_name":"Test User","user_email":"test@example.com","credential_id":"test_credential","access_token":"test_token"}`
	s, err := provider.UnmarshalSession(sessionJSON)
	a.NoError(err)

	session := s.(*passkey.Session)
	a.Equal("test_challenge", session.Challenge)
	a.Equal("test_user", session.UserID)
	a.Equal("Test User", session.UserName)
	a.Equal("test@example.com", session.UserEmail)
	a.Equal("test_credential", session.CredentialID)
	a.Equal("test_token", session.AccessToken)
}

func Test_RefreshTokenAvailable(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()
	a.False(provider.RefreshTokenAvailable())
}

func Test_RefreshToken(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()

	_, err := provider.RefreshToken("test_token")
	a.Error(err)
	a.Contains(err.Error(), "refresh token is not supported")
}

func Test_SetName(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()

	provider.SetName("custom_passkey")
	a.Equal("custom_passkey", provider.Name())
}

func Test_SetRelyingParty(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()

	provider.SetRelyingParty("example.com")
	a.Equal("example.com", provider.RelyingParty)
}

func Test_SetOrigin(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()

	provider.SetOrigin("https://example.com")
	a.Equal("https://example.com", provider.Origin)
}

func Test_BeginRegistrationEndpoint(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()

	req := &passkey.RegistrationRequest{
		UserID:      "test_user_123",
		UserName:    "testuser",
		DisplayName: "Test User",
		Email:       "test@example.com",
	}

	resp, err := provider.BeginRegistrationEndpoint(req)
	a.NoError(err)
	a.True(resp.Success)
	a.Equal("test_user_123", resp.UserID)
	a.NotEmpty(resp.SessionID)
	a.NotEmpty(resp.Challenge)
	a.NotNil(resp.Options)
	a.Equal("Registration challenge generated successfully", resp.Message)
}

func Test_BeginRegistrationEndpoint_MissingFields(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()

	req := &passkey.RegistrationRequest{
		UserID: "test_user_123",
		// Missing UserName and DisplayName
	}

	resp, err := provider.BeginRegistrationEndpoint(req)
	a.Error(err)
	a.False(resp.Success)
	a.Contains(resp.Message, "required")
}

func Test_FinishRegistrationEndpoint(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()

	req := &passkey.FinishRegistrationRequest{
		SessionID:  "test_session_123",
		UserID:     "test_user_123",
		Credential: map[string]interface{}{"id": "test_credential", "type": "public-key"},
	}

	resp, err := provider.FinishRegistrationEndpoint(req)
	a.NoError(err)
	a.True(resp.Success)
	a.NotNil(resp.Credential)
	a.NotNil(resp.User)
	a.Equal("test_user_123", resp.User.UserID)
	a.Equal("passkey", resp.User.Provider)
	a.Equal("Registration completed successfully", resp.Message)

	// Check raw data
	a.NotNil(resp.User.RawData)
	a.Equal("mock_credential_id", resp.User.RawData["credential_id"])
	a.Equal(true, resp.User.RawData["registration_complete"])
	a.Equal("test_session_123", resp.User.RawData["session_id"])
}

func Test_FinishRegistrationEndpoint_MissingFields(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()

	req := &passkey.FinishRegistrationRequest{
		SessionID: "test_session_123",
		// Missing UserID and Credential
	}

	resp, err := provider.FinishRegistrationEndpoint(req)
	a.Error(err)
	a.False(resp.Success)
	a.Contains(resp.Message, "required")
}

func Test_BeginLoginEndpoint(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()

	resp, err := provider.BeginLoginEndpoint("test_user_123")
	a.NoError(err)
	a.True(resp.Success)
	a.Equal("test_user_123", resp.UserID)
	a.NotEmpty(resp.SessionID)
	a.NotEmpty(resp.Challenge)
	a.NotNil(resp.Options)
	a.Equal("Login challenge generated successfully", resp.Message)
}

func Test_BeginLoginEndpoint_EmptyUserID(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()

	resp, err := provider.BeginLoginEndpoint("")
	a.Error(err)
	a.False(resp.Success)
	a.Contains(resp.Message, "user_id is required")
}

// Note: Controller tests have been moved to the main controllers.go file
// The passkey provider now only contains the core endpoint methods

func passkeyProvider() *passkey.Provider {
	return passkey.New("localhost", "http://localhost:3000", "/callback")
}
