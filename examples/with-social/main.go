// Package main demonstrates FiberAuth with Social/OAuth providers.
// This example shows how to integrate Google and GitHub OAuth authentication.
package main

import (
	"log"
	"os"

	"github.com/gofiber/fiber/v3"
	"github.com/izetmolla/fiberauth"
	"github.com/izetmolla/fiberauth/social/providers/github"
	"github.com/izetmolla/fiberauth/social/providers/google"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	// 1. Initialize database
	db, err := gorm.Open(sqlite.Open("auth.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// 2. Configure social providers
	// Providers must be cast to []interface{} for the Config
	var providers []interface{}

	if os.Getenv("GOOGLE_CLIENT_ID") != "" {
		googleProvider := google.New(
			os.Getenv("GOOGLE_CLIENT_ID"),
			os.Getenv("GOOGLE_CLIENT_SECRET"),
			"http://localhost:3000/auth/google/callback",
			"email", "profile",
		)
		providers = append(providers, googleProvider)
	}

	if os.Getenv("GITHUB_CLIENT_ID") != "" {
		githubProvider := github.New(
			os.Getenv("GITHUB_CLIENT_ID"),
			os.Getenv("GITHUB_CLIENT_SECRET"),
			"http://localhost:3000/auth/github/callback",
			"user:email",
		)
		providers = append(providers, githubProvider)
	}

	// 3. Initialize FiberAuth with social providers
	authRedirectURL := "http://localhost:3000/auth/callback"

	auth, err := fiberauth.New(&fiberauth.Config{
		JWTSecret:       "your-secret-key-change-in-production",
		DbClient:        db,
		Providers:       providers,
		AuthRedirectURL: &authRedirectURL,
		Debug:           true,
	})
	if err != nil {
		log.Fatal("Failed to initialize auth:", err)
	}

	// 4. Create Fiber app
	app := fiber.New(fiber.Config{
		AppName: "FiberAuth with Social Auth Example",
	})

	// 5. Public routes
	app.Get("/", func(c fiber.Ctx) error {
		return c.SendString(`
<!DOCTYPE html>
<html>
<head>
    <title>Social Auth Example</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .auth-buttons { margin: 20px 0; }
        button { padding: 10px 20px; margin: 5px; cursor: pointer; }
        .google { background: #4285f4; color: white; border: none; }
        .github { background: #333; color: white; border: none; }
        .traditional { background: #28a745; color: white; border: none; }
    </style>
</head>
<body>
    <h1>FiberAuth Social Authentication</h1>
    <p>Choose your authentication method:</p>
    
    <div class="auth-buttons">
        <h3>Social Login:</h3>
        <button class="google" onclick="window.location.href='/auth/google'">
            🔐 Sign in with Google
        </button>
        <button class="github" onclick="window.location.href='/auth/github'">
            🔐 Sign in with GitHub
        </button>
    </div>

    <div class="auth-buttons">
        <h3>Traditional Login:</h3>
        <button class="traditional" onclick="window.location.href='/login'">
            📧 Sign in with Email
        </button>
    </div>

    <h3>Available Providers:</h3>
    <ul id="providers"></ul>

    <script>
        fetch('/auth/providers')
            .then(r => r.json())
            .then(providers => {
                const list = document.getElementById('providers');
                providers.forEach(p => {
                    const li = document.createElement('li');
                    li.textContent = p;
                    list.appendChild(li);
                });
            });
    </script>
</body>
</html>
		`)
	})

	// 6. Traditional auth routes
	app.Post("/auth/signup", auth.SignUpController)
	app.Post("/auth/signin", auth.SignInController)
	app.Post("/auth/signout", auth.SignOutController)

	// 7. Social auth routes
	app.Get("/auth/providers", auth.ProvidersController)
	app.Get("/auth/:provider", auth.ProviderLoginController)
	app.Get("/auth/:provider/callback", auth.ProviderCallBackController)

	// 8. Protected routes
	app.Get("/dashboard", auth.UseAuth(&fiberauth.AuthConfig{
		OnlyAPI:          false,
		RedirectToSignIn: true,
	}), func(c fiber.Ctx) error {
		sessionID := auth.GetSessionID(c)
		session, err := auth.GetSession(sessionID)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Unauthorized",
			})
		}

		return c.JSON(fiber.Map{
			"message": "Dashboard",
			"user_id": session.UserID,
			"roles":   session.Roles,
		})
	})

	// 9. API routes
	api := app.Group("/api")
	api.Use(auth.UseAuth(&fiberauth.AuthConfig{
		OnlyAPI: true,
	}))

	api.Get("/profile", func(c fiber.Ctx) error {
		userClaims, err := fiberauth.GetUser(c.Locals("user"))
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"user": userClaims,
		})
	})

	// 10. Start server
	log.Println("Server starting on http://localhost:3000")
	log.Println("Social providers configured:")
	for name := range auth.GetProviders() {
		log.Printf("  - %s", name)
	}
	log.Fatal(app.Listen(":3000"))
}

/*
Setup Instructions:

1. Set environment variables:
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"
export GITHUB_CLIENT_ID="your-github-client-id"
export GITHUB_CLIENT_SECRET="your-github-client-secret"

2. Configure OAuth redirect URLs in provider dashboards:
Google: http://localhost:3000/auth/google/callback
GitHub: http://localhost:3000/auth/github/callback

3. Run the example:
go run main.go

4. Visit http://localhost:3000 and click on social login buttons

Flow:
1. User clicks "Sign in with Google"
2. Redirected to /auth/google
3. Redirected to Google OAuth consent page
4. User authorizes
5. Google redirects to /auth/google/callback
6. FiberAuth creates/finds user and creates session
7. User redirected back with authentication complete
*/
