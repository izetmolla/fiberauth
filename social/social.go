package social

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/extractors"
	"github.com/gofiber/fiber/v3/middleware/session"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

const SessionName = "_auth_session"

// ProviderParamKey can be used as a key in context when passing in a provider
const ProviderParamKey key = iota

// Session can/should be set by applications using auth. The default is a cookie store.
var (
	ErrSessionNil = errors.New("authentication/auth: no JWT_SECRET environment variable is set. The default cookie store is not available and any calls will fail. Ignore this warning if you are using a different store")
)

type key int

type SocialDataConfig struct {
	RedisStorage *redis.Client // Existing Redis client to reuse
	SQLStorage   *gorm.DB      // Existing GORM database client to reuse
	Debug        bool          // Enable debug mode for storage operations
}
type SocialData struct {
	store *session.Store
	sql   *gorm.DB
}

// SetDebug enables or disables debug mode for the storage.
func (s *SocialData) SetDebug(debug bool) {
	if s.store != nil && s.store.Storage != nil {
		if gormStorage, ok := s.store.Storage.(*GormStorage); ok {
			gormStorage.SetDebug(debug)
		}
	}
}

// IsDebug returns whether debug mode is enabled for the storage.
func (s *SocialData) IsDebug() bool {
	if s.store != nil && s.store.Storage != nil {
		if gormStorage, ok := s.store.Storage.(*GormStorage); ok {
			return gormStorage.IsDebug()
		}
	}
	return false
}

// GetStorageStats returns storage statistics if debug mode is enabled.
func (s *SocialData) GetStorageStats() (map[string]interface{}, error) {
	if s.store != nil && s.store.Storage != nil {
		if gormStorage, ok := s.store.Storage.(*GormStorage); ok {
			return gormStorage.GetStats()
		}
	}
	return nil, fmt.Errorf("storage stats not available or debug mode not enabled")
}

// New creates a new SocialData instance with the provided configuration.
func New(cnf *SocialDataConfig) *SocialData {
	if cnf == nil {
		return &SocialData{}
	}

	app := &SocialData{}
	storage := createStorage(cnf)
	app.store = createSessionStore(storage)

	return app
}

// createStorage creates the appropriate storage implementation based on configuration.
func createStorage(cnf *SocialDataConfig) StorageInterface {
	if cnf.RedisStorage != nil {
		return NewRedisStorage(cnf.RedisStorage)
	}
	if cnf.SQLStorage != nil {
		if cnf.Debug {
			return NewGormStorageWithDebug(cnf.SQLStorage, true)
		}
		return NewGormStorage(cnf.SQLStorage)
	}
	return nil
}

// createSessionStore creates a session store with the given storage implementation.
func createSessionStore(storage StorageInterface) *session.Store {
	config := session.Config{
		CookieHTTPOnly: true,
		Extractor:      extractors.FromCookie(SessionName),
	}

	if storage != nil {
		config.Storage = storage
	}

	return session.NewStore(config)
}

// Options that affect how CompleteUserAuth works.
type CompleteUserAuthOptions struct {
	// True if CompleteUserAuth should automatically end the user's session.
	//
	// Defaults to True.
	ShouldLogout bool
}

/*
BeginAuthHandler is a convenience handler for starting the authentication process.
It expects to be able to get the name of the provider from the query parameters
as either "provider" or ":provider".

BeginAuthHandler will redirect the user to the appropriate authentication end-point
for the requested provider.

See https://github.com/markbates/authentication/examples/main.go to see this in action.
*/
func (c *SocialData) BeginAuthHandler(ctx fiber.Ctx, provider Provider) (string, error) {
	url, err := c.GetAuthURL(ctx, provider)
	if err != nil {
		return "", err
	}

	return url, nil
}

/*
CompleteUserAuth does what it says on the tin. It completes the authentication
process and fetches all of the basic information about the user from the provider.

It expects to be able to get the name of the provider from the query parameters
as either "provider" or ":provider".

This method automatically ends the session. You can prevent this behavior by
passing in options. Please note that any options provided in addition to the
first will be ignored.

See https://github.com/markbates/authentication/examples/main.go to see this in action.
*/
func (c *SocialData) CompleteUserAuth(ctx fiber.Ctx, provider Provider, options ...CompleteUserAuthOptions) (User, error) {
	if c.store == nil {
		return User{}, ErrSessionNil
	}

	value, err := c.GetFromSession(provider.Name(), ctx)
	if err != nil {
		return User{}, err
	}

	shouldLogout := true
	if len(options) > 0 && !options[0].ShouldLogout {
		shouldLogout = false
	}

	if shouldLogout {
		defer c.Logout(ctx)
	}

	sess, err := provider.UnmarshalSession(value)
	if err != nil {
		return User{}, err
	}

	err = validateState(ctx, sess)
	if err != nil {
		return User{}, err
	}

	user, err := provider.FetchUser(sess)
	if err == nil {
		// user can be found with existing session data
		return user, err
	}

	// get new token and retry fetch
	_, err = sess.Authorize(provider, &ParamsV3{ctx: ctx})
	if err != nil {
		return User{}, err
	}

	err = c.StoreInSession(provider.Name(), sess.Marshal(), ctx)

	if err != nil {
		return User{}, err
	}

	gu, err := provider.FetchUser(sess)
	return gu, err
}

/*
GetAuthURL starts the authentication process with the requested provided.
It will return a URL that should be used to send users to.

It expects to be able to get the name of the provider from the query parameters
as either "provider" or ":provider".

I would recommend using the BeginAuthHandler instead of doing all of these steps
yourself, but that's entirely up to you.
*/
func (c *SocialData) GetAuthURL(ctx fiber.Ctx, provider Provider) (string, error) {
	if c.store == nil {
		return "", ErrSessionNil
	}

	sess, err := provider.BeginAuth(c.SetState(ctx))
	if err != nil {
		return "", err
	}

	url, err := sess.GetAuthURL()
	if err != nil {
		return "", err
	}

	err = c.StoreInSession(provider.Name(), sess.Marshal(), ctx)
	if err != nil {
		return "", err
	}

	return url, err
}

// Logout invalidates a user session.
func (c *SocialData) Logout(ctx fiber.Ctx) error {
	session, err := c.store.Get(ctx)
	if err != nil {
		return err
	}

	if err := session.Destroy(); err != nil {
		return err
	}

	return nil
}

// GetFromSession retrieves a previously-stored value from the session.
// If no value has previously been stored at the specified key, it will return an error.
func (c *SocialData) GetFromSession(key string, ctx fiber.Ctx) (string, error) {
	session, err := c.store.Get(ctx)
	if err != nil {
		return "", err
	}

	value, err := getSessionValue(session, key)
	if err != nil {
		return "", errors.New("could not find a matching session for this request")
	}

	return value, nil
}

// SetState sets the state string associated with the given request.
// If no state string is associated with the request, one will be generated.
// This state is sent to the provider and can be retrieved during the
// callback.
func (c *SocialData) SetState(ctx fiber.Ctx) string {
	state := ctx.Query("state")
	if len(state) > 0 {
		return state
	}

	// If a state query param is not passed in, generate a random
	// base64-encoded nonce so that the state on the auth URL
	// is unguessable, preventing CSRF attacks, as described in
	//
	// https://auth0.com/docs/protocols/oauth2/oauth-state#keep-reading
	nonceBytes := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, nonceBytes)
	if err != nil {
		panic("auth: source of randomness unavailable: " + err.Error())
	}
	return base64.URLEncoding.EncodeToString(nonceBytes)
}

// StoreInSession stores a specified key/value pair in the session.
func (c *SocialData) StoreInSession(key string, value string, ctx fiber.Ctx) error {
	session, err := c.store.Get(ctx)
	if err != nil {
		return err
	}

	if err := updateSessionValue(session, key, value); err != nil {
		return err
	}

	// saved here
	session.Save()
	return nil
}

func getSessionValue(store *session.Session, key string) (string, error) {
	value := store.Get(key)
	if value == nil {
		return "", errors.New("could not find a matching session for this request")
	}

	valueStr, ok := value.(string)
	if !ok {
		return "", errors.New("session value is not a string")
	}

	rdata := strings.NewReader(valueStr)
	r, err := gzip.NewReader(rdata)
	if err != nil {
		return "", err
	}
	s, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}

	return string(s), nil
}

// validateState ensures that the state token param from the original
// AuthURL matches the one included in the current (callback) request.
func validateState(ctx fiber.Ctx, sess Session) error {
	rawAuthURL, err := sess.GetAuthURL()
	if err != nil {
		return err
	}

	authURL, err := url.Parse(rawAuthURL)
	if err != nil {
		return err
	}

	originalState := authURL.Query().Get("state")
	if originalState != "" && (originalState != ctx.Query("state")) {
		return errors.New("state token mismatch")
	}
	return nil
}

func updateSessionValue(session *session.Session, key, value string) error {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write([]byte(value)); err != nil {
		return err
	}
	if err := gz.Flush(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}

	session.Set(key, b.String())

	return nil
}
