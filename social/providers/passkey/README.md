# Passkey Provider for FiberAuth

The Passkey provider enables WebAuthn-based passwordless authentication using passkeys. This provider implements the `social.Provider` interface and provides secure authentication without passwords, following the same structure as other social providers like Google and GitHub.

## Features

- **Passwordless Authentication**: Users can authenticate using biometric data, security keys, or device-stored credentials
- **WebAuthn Standard**: Built on the W3C WebAuthn specification
- **High Security**: Cryptographic authentication with public/private key pairs
- **Cross-Platform**: Works across different devices and platforms
- **Consistent API**: Follows the same pattern as other social providers

## Installation

Make sure to install the WebAuthn library dependency:

```bash
go get github.com/go-webauthn/webauthn
```

## Usage

### Basic Setup

```go
package main

import (
    "github.com/izetmolla/fiberauth/social"
    "github.com/izetmolla/fiberauth/social/providers/passkey"
)

func main() {
    // Create a new passkey provider
    provider := passkey.New(
        "localhost",                    // Relying Party ID
        "http://localhost:3000",        // Origin
        "http://localhost:3000/auth/passkey/callback", // Callback URL
    )
    
    // Register the provider
    social.UseProviders(provider)
}
```

### Integration with FiberAuth

```go
// In your FiberAuth configuration
providers := []social.ProviderOptions{
    {
        Name:     "passkey",
        CallBack: "http://localhost:3000/auth/passkey/callback",
        Config:   json.RawMessage(`{"rp_id": "localhost", "origin": "http://localhost:3000"}`),
    },
}
```

### Provider Configuration

The passkey provider supports several configuration methods:

```go
provider := passkey.New("localhost", "http://localhost:3000", "/callback")

// Set custom provider name (useful for multiple instances)
provider.SetName("custom_passkey")

// Update configuration
provider.SetRelyingParty("example.com")
provider.SetOrigin("https://example.com")
```

### Client-Side Integration

Since passkeys require client-side WebAuthn API calls, you'll need JavaScript to handle the authentication flow:

```javascript
// Registration flow
async function registerPasskey() {
    // Get registration options from your server
    const response = await fetch('/auth/passkey/begin-registration');
    const options = await response.json();
    
    // Call WebAuthn API
    const credential = await navigator.credentials.create({
        publicKey: options
    });
    
    // Send credential back to server
    await fetch('/auth/passkey/finish-registration', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(credential)
    });
}

// Authentication flow
async function authenticatePasskey() {
    // Get authentication options from your server
    const response = await fetch('/auth/passkey/begin-login');
    const options = await response.json();
    
    // Call WebAuthn API
    const assertion = await navigator.credentials.get({
        publicKey: options
    });
    
    // Send assertion back to server
    await fetch('/auth/passkey/finish-login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(assertion)
    });
}
```

## API Reference

### Provider Methods

- `New(relyingParty, origin, callbackURL string) *Provider`: Creates a new passkey provider
- `Name() string`: Returns the provider name
- `SetName(name string)`: Sets a custom provider name
- `BeginAuth(state string) (social.Session, error)`: Initiates the authentication process
- `FetchUser(session social.Session) (social.User, error)`: Retrieves user information after authentication
- `RefreshTokenAvailable() bool`: Returns false (passkeys don't use refresh tokens)
- `RefreshToken(refreshToken string) (*oauth2.Token, error)`: Not supported for passkeys
- `SetRelyingParty(rp string)`: Sets the relying party
- `SetOrigin(origin string)`: Sets the origin
- `BeginRegistration(userID, userName, userDisplayName string)`: Starts passkey registration
- `FinishRegistration(user, sessionData, response)`: Completes passkey registration
- `FinishLogin(user, sessionData, response)`: Completes passkey authentication

### Session Structure

The passkey session contains:
- `Challenge`: WebAuthn challenge string
- `UserID`: User identifier
- `UserName`: Username
- `UserEmail`: User email
- `CredentialID`: Credential identifier
- `AccessToken`: Access token (for compatibility)
- `SessionData`: WebAuthn session data
- `Options`: WebAuthn options

### Session Methods

- `GetAuthURL() (string, error)`: Returns challenge data or WebAuthn options as JSON
- `Authorize(provider, params) (string, error)`: Processes authentication response
- `Marshal() string`: Serializes session to JSON
- `String() string`: Returns marshaled session
- `UnmarshalSession(data string) (social.Session, error)`: Deserializes session from JSON

## Example Usage

### Basic Authentication Flow

```go
// 1. Create provider
provider := passkey.New("localhost", "http://localhost:3000", "/callback")

// 2. Begin authentication
session, err := provider.BeginAuth("unique_state")
if err != nil {
    // Handle error
}

// 3. Get challenge data for client
authURL, err := session.GetAuthURL()
if err != nil {
    // Handle error
}
// authURL contains the challenge data for WebAuthn API

// 4. After client completes WebAuthn, authorize session
params := &MockParams{
    values: map[string]string{
        "user_id":       "user123",
        "user_name":     "John Doe",
        "user_email":    "john@example.com",
        "credential_id": "cred456",
    },
}
token, err := session.Authorize(provider, params)

// 5. Fetch user information
user, err := provider.FetchUser(session)
```

## Security Considerations

1. **HTTPS Required**: WebAuthn requires HTTPS in production environments
2. **Origin Validation**: Ensure the origin matches your domain exactly
3. **Challenge Validation**: Always validate challenges server-side
4. **Credential Storage**: Store user credentials securely in your database
5. **Timeout Handling**: Implement appropriate timeouts for authentication flows
6. **Replay Attack Prevention**: Ensure challenges are used only once

## Browser Support

Passkeys are supported in modern browsers:
- Chrome 67+
- Firefox 60+
- Safari 14+
- Edge 18+

## Testing

Run the test suite:

```bash
go test -v
```

The provider includes comprehensive tests covering:
- Provider creation and configuration
- Authentication flows
- Session management
- Error handling
- JSON serialization/deserialization

## Example Implementation

See the test files (`passkey_test.go` and `session_test.go`) for detailed example usage and implementation patterns.

## Comparison with Other Providers

The passkey provider follows the same interface as other social providers:

| Feature | Google | GitHub | Passkey |
|---------|--------|--------|---------|
| OAuth2 Flow | ✅ | ✅ | ❌ |
| Refresh Tokens | ✅ | ❌ | ❌ |
| Client-Side Auth | ❌ | ❌ | ✅ |
| Passwordless | ❌ | ❌ | ✅ |
| Biometric Auth | ❌ | ❌ | ✅ |

## Contributing

When contributing to the passkey provider:
1. Follow the existing provider patterns from other social providers
2. Ensure all tests pass
3. Add appropriate error handling
4. Update documentation as needed
5. Follow Go coding standards

## License

This provider is part of the FiberAuth project and follows the same license terms.