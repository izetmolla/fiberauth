package fiberauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"

	"github.com/izetmolla/fiberauth"
	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers"
)

func buildApp(t *testing.T) *fiber.App {
	t.Helper()
	auth, err := goauth.New(goauth.Config{
		Secret:    []string{"fiber-secret"},
		TrustHost: true,
		Tokens:    goauth.TokensConfig{Enabled: true},
		Providers: []goauth.Provider{
			providers.Credentials(providers.CredentialsOptions{
				Authorize: func(_ context.Context, c map[string]string, _ *http.Request) (*goauth.User, error) {
					switch c["email"] {
					case "admin@zion.io":
						return &goauth.User{ID: "1", Name: "Admin", Email: c["email"]}, nil
					case "tank@zion.io":
						return &goauth.User{ID: "9", Name: "Tank", Email: c["email"]}, nil
					}
					return nil, nil
				},
			}),
		},
		Callbacks: goauth.Callbacks{
			JWT: func(_ context.Context, p goauth.JWTCallbackParams) (goauth.JWT, error) {
				if p.User != nil && p.User.Email == "admin@zion.io" {
					p.Token["roles"] = []string{"admin", "member"}
				} else if p.User != nil {
					p.Token["roles"] = []string{"member"}
				}
				return p.Token, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	app := fiber.New()
	app.All("/auth/*", fiberauth.Handler(auth))
	app.Get("/me", fiberauth.Protect(auth), func(c fiber.Ctx) error {
		return c.JSON(fiberauth.SessionFrom(c))
	})
	app.Get("/admin", fiberauth.Guard(auth, fiberauth.HasRole("admin")), func(c fiber.Ctx) error {
		return c.SendString("admin area")
	})
	return app
}

func tokenFor(t *testing.T, app *fiber.App, email string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, "/auth/callback/credentials",
		strings.NewReader(url.Values{"email": {email}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Auth-Flow", "token")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("signin: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("signin status: %d", resp.StatusCode)
	}
	var tok goauth.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return tok.AccessToken
}

func do(t *testing.T, app *fiber.App, method, path, bearer string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

func TestFiberProtectAndBearer(t *testing.T) {
	app := buildApp(t)

	if r := do(t, app, http.MethodGet, "/me", ""); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", r.StatusCode)
	}

	token := tokenFor(t, app, "tank@zion.io")
	r := do(t, app, http.MethodGet, "/me", token)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with bearer, got %d", r.StatusCode)
	}
	var session goauth.Session
	if err := json.NewDecoder(r.Body).Decode(&session); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if session.User == nil || session.User.Email != "tank@zion.io" {
		t.Fatalf("unexpected user: %#v", session.User)
	}
}

func TestFiberRoleGuard(t *testing.T) {
	app := buildApp(t)

	// A member is authenticated but lacks the admin role -> 403.
	memberToken := tokenFor(t, app, "tank@zion.io")
	if r := do(t, app, http.MethodGet, "/admin", memberToken); r.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for member on /admin, got %d", r.StatusCode)
	}

	// An admin passes the role guard -> 200.
	adminToken := tokenFor(t, app, "admin@zion.io")
	if r := do(t, app, http.MethodGet, "/admin", adminToken); r.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for admin on /admin, got %d", r.StatusCode)
	}

	// No session at all -> 401.
	if r := do(t, app, http.MethodGet, "/admin", ""); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 anonymous on /admin, got %d", r.StatusCode)
	}
}

func TestFiberProvidersEndpoint(t *testing.T) {
	app := buildApp(t)
	resp := do(t, app, http.MethodGet, "/auth/providers", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var out map[string]goauth.PublicProvider
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := out["credentials"]; !ok {
		t.Fatalf("expected credentials provider, got %#v", out)
	}
}
