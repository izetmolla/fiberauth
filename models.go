package fiberauth

import (
	"encoding/json"
	"time"

	"gorm.io/gorm"
)

// Server specific settings.
type Session struct {
	ID     string `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID string `json:"user_id" gorm:"type:string;default:null"`

	IPAddress *string    `json:"ip_address" gorm:"column:ip_address;size:100;default:null"` // IPv4 or IPv6
	UserAgent *string    `json:"user_agent" gorm:"type:text;default:null"`                  // User agent string
	ExpiresAt *time.Time `json:"expires_at" gorm:"default:null"`                            // Expiration time for the session, defaults to 1 year from now

	Method string `json:"method" gorm:"type:string;default:'credentials'"` // Authorization type (credentials, social, etc.)

	CreatedAt time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}

// TableName specifies the table name for Session.
// This can be overridden by setting SessionModelTable in Authorization struct.
func (Session) TableName() string {
	return "sessions"
}

type User struct {
	ID        string          `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Username  *string         `json:"username"`
	FirstName string          `json:"first_name"`
	LastName  string          `json:"last_name"`
	AvatarURL string          `json:"avatar_url"`
	Email     string          `json:"email"`
	Roles     json.RawMessage `json:"roles" gorm:"type:jsonb;default:'[]';not null"`
	Metadata  json.RawMessage `json:"metadata" gorm:"type:jsonb;default:'{}';not null"`
	Options   json.RawMessage `json:"options" gorm:"type:jsonb;default:'{}';not null"`
	Password  *string         `json:"password"`

	CreatedAt time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}

// TableName specifies the table name for User.
// This can be overridden by setting UsersModelTable in Authorization struct.
func (User) TableName() string {
	return "users"
}
