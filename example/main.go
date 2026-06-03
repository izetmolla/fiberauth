// Command fiber-example is a self-contained Fiber v3 server wired to goauth. It
// shows the token (API) flow plus role-based route guards.
//
//	# member (gets 403 on /admin):
//	curl -s -XPOST -H 'X-Auth-Flow: token' -d 'email=member@example.com' localhost:3001/auth/callback/credentials
//	# admin (gets 200 on /admin):
//	curl -s -XPOST -H 'X-Auth-Flow: token' -d 'email=admin@example.com'  localhost:3001/auth/callback/credentials
//	curl -s localhost:3001/admin -H "Authorization: Bearer <accessToken>"
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/gofiber/fiber/v3"

	"github.com/izetmolla/fiberauth"
	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/credentials"
)

func main() {
	auth, err := goauth.New(goauth.Config{
		Secret:    []string{getenv("AUTH_SECRET", "dev-secret-change-me")},
		TrustHost: true,
		Tokens:    goauth.TokensConfig{Enabled: true},
		Providers: []goauth.Provider{
			credentials.New(credentials.Options{
				Authorize: func(_ context.Context, c map[string]string, _ *http.Request) (*goauth.User, error) {
					// Demo: any known email signs in; password ignored.
					email := c["email"]
					if email == "admin@example.com" || email == "member@example.com" {
						return &goauth.User{ID: email, Name: email, Email: email}, nil
					}
					return nil, nil
				},
			}),
		},
		Callbacks: goauth.Callbacks{
			// Roles are attached here and surface on session.Roles().
			JWT: func(_ context.Context, p goauth.JWTCallbackParams) (goauth.JWT, error) {
				if p.User != nil && p.User.Email == "admin@example.com" {
					p.Token["roles"] = []string{"admin", "member"}
				} else if p.User != nil {
					p.Token["roles"] = []string{"member"}
				}
				return p.Token, nil
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	app := fiber.New()
	app.All("/auth/*", fiberauth.Handler(auth))

	// Requires any authenticated user.
	app.Get("/me", fiberauth.Protect(auth), func(c fiber.Ctx) error {
		return c.JSON(fiberauth.SessionFrom(c))
	})

	// Requires the "admin" role; members get 403, anonymous get 401.
	app.Get("/admin", fiberauth.Guard(auth, fiberauth.HasRole("admin")), func(c fiber.Ctx) error {
		s := fiberauth.SessionFrom(c)
		return c.JSON(fiber.Map{"area": "admin", "user": s.User, "roles": s.Roles()})
	})

	addr := getenv("ADDR", ":3001")
	log.Printf("goauth fiber example listening on %s", addr)
	log.Fatal(app.Listen(addr))
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
