// Package config provides configuration options following Go best practices
package config

import (
	"time"
)

// Option is a functional option for configuring Authorization
type Option func(*Config)

// WithDebug enables debug mode
func WithDebug(debug bool) Option {
	return func(c *Config) {
		c.Debug = debug
	}
}

// WithRedis configures Redis client and settings
func WithRedis(client interface{}, prefix string, ttl time.Duration) Option {
	return func(c *Config) {
		c.RedisKeyPrefix = prefix
		c.RedisTTL = &ttl
	}
}

// WithTokenLifetimes configures JWT token lifetimes
func WithTokenLifetimes(accessLifetime, refreshLifetime string) Option {
	return func(c *Config) {
		c.AccessTokenLifetime = &accessLifetime
		c.RefreshTokenLifetime = &refreshLifetime
	}
}

// WithPasswordPolicy configures password requirements
func WithPasswordPolicy(cost, minLength int) Option {
	return func(c *Config) {
		c.PasswordCost = &cost
		c.PasswordMinLength = &minLength
	}
}

// WithCookieSettings configures session cookie settings
func WithCookieSettings(sessionName, domain, redirectURL string) Option {
	return func(c *Config) {
		c.CookieSessionName = &sessionName
		c.MainDomainName = &domain
		c.AuthRedirectURL = &redirectURL
	}
}

// WithCustomTables configures custom database table names
func WithCustomTables(usersTable, sessionsTable, storageTable string) Option {
	return func(c *Config) {
		c.UsersModelTable = usersTable
		c.SessionModelTable = sessionsTable
		c.StorageTableName = storageTable
	}
}

// WithSocialProviders configures social authentication providers
func WithSocialProviders(providers ...interface{}) Option {
	return func(c *Config) {
		c.Providers = append(c.Providers, providers...)
	}
}

