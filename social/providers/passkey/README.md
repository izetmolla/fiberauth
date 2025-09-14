# Passkey Provider for FiberAuth

The Passkey provider enables WebAuthn-based passwordless authentication using passkeys. This provider implements the `social.Provider` interface and provides secure authentication without passwords.

## Features

- **Passwordless Authentication**: Users can authenticate using biometric data, security keys, or device-stored credentials
- **WebAuthn Standard**: Built on the W3C WebAuthn specification
- **High Security**: Cryptographic authentication with public/private key pairs
- **Cross-Platform**: Works across different devices and platforms

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
    provider, err := passkey.New(
        "localhost",                    // Relying Party ID
        "http://localhost:3000",        // Origin
        "http://localhost:3000/auth/passkey/callback", // Callback URL
    )
    if err != nil {
        panic(err)
    }
    
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
        body: JSON.stringify(assertion)
    });
}
```

## API Reference

### Provider Methods

- `New(relyingParty, origin, callbackURL string) (*Provider, error)`: Creates a new passkey provider
- `BeginAuth(state string) (social.Session, error)`: Initiates the authentication process
- `FetchUser(session social.Session) (social.User, error)`: Retrieves user information after authentication
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
- `SessionData`: WebAuthn session data
- `Options`: WebAuthn options

## Security Considerations

1. **HTTPS Required**: WebAuthn requires HTTPS in production environments
2. **Origin Validation**: Ensure the origin matches your domain exactly
3. **Challenge Validation**: Always validate challenges server-side
4. **Credential Storage**: Store user credentials securely in your database
5. **Timeout Handling**: Implement appropriate timeouts for authentication flows

## Browser Support

Passkeys are supported in modern browsers:
- Chrome 67+
- Firefox 60+
- Safari 14+
- Edge 18+

## Example Implementation

See the test files (`passkey_test.go` and `session_test.go`) for example usage and implementation patterns.

## Contributing

When contributing to the passkey provider:
1. Follow the existing provider patterns from other social providers
2. Ensure all tests pass
3. Add appropriate error handling
4. Update documentation as needed

## License

This provider is part of the FiberAuth project and follows the same license terms.
