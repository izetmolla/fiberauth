package fiberauth

import "time"

var (
	// RefreshTokenHandlerIdentifier is the key used to identify refresh token requests
	RefreshTokenHandlerIdentifier = "cft"

	// ReauthorizeHandlerIdentifier is the key used to identify reauthorization requests
	ReauthorizeHandlerIdentifier = "cra"

	// defaultAccessTokenLifetime is the default lifetime for access tokens
	defaultAccessTokenLifetime = "30s"

	// defaultRefreshTokenLifetime is the default lifetime for refresh tokens
	defaultRefreshTokenLifetime = "1h"

	// defaultSigningMethodHMAC is the default JWT signing method
	defaultSigningMethodHMAC = "HS256"

	// defaultRedisTTL is the default TTL for Redis session storage
	defaultRedisTTL = 60 * 30 * time.Second

	// defaultRedisPrefix is the default prefix for Redis keys
	defaultRedisPrefix = "AUTHSESSIONS"

	// defaultCookieSessionName is the default name for the session cookie
	defaultCookieSessionName = "cnf.id"

	// defaultMainDomainName is the default domain name for the session cookie
	defaultMainDomainName = "localhost"

	// defaultAuthRedirectURL is the default redirect URL for the auth server
	defaultAuthRedirectURL = ""
)
