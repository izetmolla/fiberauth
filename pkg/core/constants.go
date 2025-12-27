// Package core provides core authentication business logic.
// This package contains the main authentication operations.
package core

const (
	// MethodCredentials represents credential-based authentication
	MethodCredentials = "credentials"
	// MethodSocial represents social/OAuth authentication
	MethodSocial = "social"
	// MethodPasskey represents passkey/WebAuthn authentication
	MethodPasskey = "passkey"
)

