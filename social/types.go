package social

import (
	"encoding/gob"
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v3"
	"gorm.io/datatypes"
)

func init() {
	gob.Register(User{})
}

const NoAuthUrlErrorMessage = "an AuthURL has not been set"

// Params is used to pass data to sessions for fiberauth. An existing
// implementation, and the one most likely to be used, is `url.Values`.
type Params interface {
	Get(string) string
}

type ParamsV3 struct {
	ctx fiber.Ctx
}

func (p *ParamsV3) Get(key string) string {
	return p.ctx.Query(key)
}

// Session needs to be implemented as part of the provider package.
// It will be marshaled and persisted between requests to "tie"
// the start and the end of the authorization process with a
// 3rd party provider.
type Session interface {
	// GetAuthURL returns the URL for the authentication end-point for the provider.
	GetAuthURL() (string, error)
	// Marshal generates a string representation of the Session for storing between requests.
	Marshal() string
	// Authorize should validate the data from the provider and return an access token
	// that can be stored for later access to the provider.
	Authorize(Provider, Params) (string, error)
}

// User contains the information common amongst most OAuth and OAuth2 providers.
// All the "raw" data from the provider can be found in the `RawData` field.
type User struct {
	RawData           map[string]any
	Provider          string         `json:"provider"`
	Email             string         `json:"email"`
	Name              string         `json:"name"`
	FirstName         string         `json:"first_name"`
	LastName          string         `json:"last_name"`
	NickName          string         `json:"nick_name"`
	Description       string         `json:"description"`
	UserID            string         `json:"user_id"`
	AvatarURL         string         `json:"avatar_url"`
	Location          string         `json:"location"`
	AccessToken       string         `json:"access_token"`
	AccessTokenSecret string         `json:"access_token_secret"`
	RefreshToken      string         `json:"refresh_token"`
	ExpiresAt         time.Time      `json:"expires_at"`
	IDToken           string         `json:"id_token"`
	Roles             datatypes.JSON `json:"roles"`
	Password          *string        `json:"password"`
}

type ProviderOptions struct {
	Name     string          `json:"name"`     // Name of the provider (e.g., "google", "apple")
	Key      string          `json:"key"`      // Client key for the provider
	Secret   string          `json:"secret"`   // Secret key for the provider
	CallBack string          `json:"callback"` // Callback URL for the provider
	Scopes   []string        `json:"scopes"`   // Scopes requested from the provider
	Config   json.RawMessage `json:"config"`   // Additional configuration options in JSON format
}
