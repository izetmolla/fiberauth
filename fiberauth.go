// Package fiberauth integrates goauth with the Fiber v3 web framework
// (github.com/gofiber/fiber/v3), analogous to the framework packages in Auth.js
// (@auth/express, @auth/sveltekit, ...). It is a standalone module so that the
// goauth core does not depend on Fiber:
//
//	import "github.com/izetmolla/fiberauth"
//
// Mount the action handler and use the middleware to load, require and
// authorize sessions:
//
//	auth, _ := goauth.New(cfg)
//	app := fiber.New()
//	app.All("/auth/*", fiberauth.Handler(auth))
//	app.Get("/me", fiberauth.Protect(auth), func(c fiber.Ctx) error {
//		return c.JSON(fiberauth.SessionFrom(c))
//	})
//	app.Get("/admin", fiberauth.Guard(auth, fiberauth.HasRole("admin")), adminHandler)
//
// Author: Izet Molla <izetmolla@icloud.com> (https://github.com/izetmolla)
package fiberauth

import (
	"net/http/httptest"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"

	"github.com/izetmolla/goauth"
)

// localsKey is where the loaded session is stored on the Fiber context.
const localsKey = "goauth.session"

// wantsJSON reports whether the client expects a JSON response, based on the
// Accept and Content-Type headers (and the XHR hint). API/SPA/mobile clients set
// these, so we can return a structured JSON error instead of Fiber's default
// text/HTML, preventing JSON.parse failures on the client.
func wantsJSON(c fiber.Ctx) bool {
	if strings.Contains(c.Get("Accept"), "application/json") {
		return true
	}
	if strings.Contains(c.Get("Content-Type"), "application/json") {
		return true
	}
	return strings.EqualFold(c.Get("X-Requested-With"), "XMLHttpRequest")
}

// errorResponse renders an auth error. For JSON clients it returns
// {"error": msg, "code": status} with the given status; otherwise it falls back
// to Fiber's default error (text/HTML via the app error handler).
func errorResponse(c fiber.Ctx, status int, msg string) error {
	if wantsJSON(c) {
		return c.Status(status).JSON(fiber.Map{"error": msg, "code": status})
	}
	return fiber.NewError(status, msg)
}

// Handler returns a fiber.Handler that serves every goauth action
// (session, csrf, providers, signin, callback, signout, token). Mount it on a
// wildcard route so all sub-paths reach it:
//
//	app.All("/auth/*", fiberauth.Handler(auth))
func Handler(a *goauth.Auth) fiber.Handler {
	return adaptor.HTTPHandler(a)
}

// GetSession reads the current session for a Fiber request. It bridges Fiber's
// fasthttp context to the net/http based core and propagates any Set-Cookie
// headers the core emits.
func GetSession(a *goauth.Auth, c fiber.Ctx) (*goauth.Session, error) {
	req, err := adaptor.ConvertRequest(c, false)
	if err != nil {
		return nil, err
	}
	rec := httptest.NewRecorder()
	session, err := a.GetSession(rec, req)
	for _, h := range rec.Header()["Set-Cookie"] {
		c.Response().Header.Add("Set-Cookie", h)
	}
	if err != nil {
		return nil, err
	}
	return session, nil
}

// SessionFrom returns the session stored by SessionLoader/Protect/Guard, or nil.
func SessionFrom(c fiber.Ctx) *goauth.Session {
	if v, ok := c.Locals(localsKey).(*goauth.Session); ok {
		return v
	}
	return nil
}

// Claim reads the named claim from the session and coerces it to T. It returns
// the value and true on success, or the zero value of T and false when the
// session is nil, the claim is absent, or it is not assignable to T:
//
//	roles, ok := fiberauth.Claim[[]string](sess, "roles")
//	uid, ok := fiberauth.Claim[string](sess, "sub")
func Claim[T any](s *goauth.Session, key string) (T, bool) {
	var zero T
	if s == nil {
		return zero, false
	}
	if v, ok := s.Claim(key).(T); ok {
		return v, true
	}
	return zero, false
}

// ClaimOr is Claim with a fallback: it returns the typed claim when present and
// assignable to T, otherwise the supplied default.
func ClaimOr[T any](s *goauth.Session, key string, fallback T) T {
	if v, ok := Claim[T](s, key); ok {
		return v
	}
	return fallback
}

// SessionLoader loads the session (if any) into the context without requiring
// it. Downstream handlers read it with SessionFrom.
func SessionLoader(a *goauth.Auth) fiber.Handler {
	return func(c fiber.Ctx) error {
		if session, err := GetSession(a, c); err == nil && session != nil {
			c.Locals(localsKey, session)
		}
		return c.Next()
	}
}

// Authorizer decides whether a request bearing the given (non-nil) session is
// allowed. Returning an error aborts with that error; returning false rejects
// with the guard's Forbidden handler.
type Authorizer func(c fiber.Ctx, s *goauth.Session) (bool, error)

// GuardConfig configures Guard. All fields are optional.
type GuardConfig struct {
	// Authorizers must all pass for the request to proceed. With none, Guard
	// only requires that a session exists.
	Authorizers []Authorizer
	// Unauthorized handles requests with no session (default: 401).
	Unauthorized fiber.Handler
	// Forbidden handles requests where an Authorizer rejected (default: 403).
	Forbidden fiber.Handler
}

// Protect is middleware that requires an authenticated session (401 otherwise).
func Protect(a *goauth.Auth) fiber.Handler {
	return Guard(a)
}

// Guard requires a session and that every Authorizer passes. It stores the
// session for SessionFrom. Use GuardWithConfig to customize responses.
func Guard(a *goauth.Auth, authorizers ...Authorizer) fiber.Handler {
	return GuardWithConfig(a, GuardConfig{Authorizers: authorizers})
}

// GuardWithConfig is Guard with custom Unauthorized/Forbidden handling.
func GuardWithConfig(a *goauth.Auth, cfg GuardConfig) fiber.Handler {
	unauthorized := cfg.Unauthorized
	if unauthorized == nil {
		unauthorized = func(c fiber.Ctx) error {
			return errorResponse(c, fiber.StatusUnauthorized, "unauthorized")
		}
	}
	forbidden := cfg.Forbidden
	if forbidden == nil {
		forbidden = func(c fiber.Ctx) error {
			return errorResponse(c, fiber.StatusForbidden, "forbidden")
		}
	}

	return func(c fiber.Ctx) error {
		session, err := GetSession(a, c)
		if err != nil {
			return errorResponse(c, fiber.StatusInternalServerError, err.Error())
		}
		if session == nil {
			return unauthorized(c)
		}
		c.Locals(localsKey, session)

		for _, authorize := range cfg.Authorizers {
			ok, err := authorize(c, session)
			if err != nil {
				return err
			}
			if !ok {
				return forbidden(c)
			}
		}
		return c.Next()
	}
}

// HasRole builds an Authorizer that passes when the session has at least one of
// the given roles (read from the "roles"/"role" claims).
func HasRole(roles ...string) Authorizer {
	return func(_ fiber.Ctx, s *goauth.Session) (bool, error) {
		return s.HasAnyRole(roles...), nil
	}
}

// HasClaim builds an Authorizer that passes when the named claim equals value.
func HasClaim(key string, value any) Authorizer {
	return func(_ fiber.Ctx, s *goauth.Session) (bool, error) {
		return s.Claim(key) == value, nil
	}
}

// Condition wraps an arbitrary predicate over the request and session, for
// custom rules (ownership checks, feature flags, request inspection, ...).
func Condition(fn func(c fiber.Ctx, s *goauth.Session) bool) Authorizer {
	return func(c fiber.Ctx, s *goauth.Session) (bool, error) {
		return fn(c, s), nil
	}
}
