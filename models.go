package fiberauth

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

var (
	// tableNameRegistry stores custom table names for User and Session models
	// This allows TableName() methods to return configured table names
	tableNameRegistry = struct {
		sync.RWMutex
		usersTable    string
		sessionsTable string
	}{
		usersTable:    "users",
		sessionsTable: "sessions",
	}
)

// SetUsersTableName sets the table name for User model.
// This is called by Authorization during initialization.
func SetUsersTableName(name string) {
	if name == "" {
		name = "users"
	}
	tableNameRegistry.Lock()
	defer tableNameRegistry.Unlock()
	tableNameRegistry.usersTable = name
}

// SetSessionsTableName sets the table name for Session model.
// This is called by Authorization during initialization.
func SetSessionsTableName(name string) {
	if name == "" {
		name = "sessions"
	}
	tableNameRegistry.Lock()
	defer tableNameRegistry.Unlock()
	tableNameRegistry.sessionsTable = name
}

// Server specific settings.
type Session struct {
	// ID is the primary key. UUIDs are generated in BeforeCreate hook for cross-database compatibility.
	// For PostgreSQL: uses uuid type, for MySQL/SQLite: uses varchar(36) or text
	ID     string `json:"id" gorm:"primaryKey;type:varchar(36)"`
	UserID string `json:"user_id" gorm:"type:varchar(255);default:null"`

	IPAddress *string    `json:"ip_address" gorm:"column:ip_address;size:100;default:null"` // IPv4 or IPv6
	UserAgent *string    `json:"user_agent" gorm:"type:text;default:null"`                  // User agent string
	ExpiresAt *time.Time `json:"expires_at" gorm:"default:null"`                            // Expiration time for the session, defaults to 1 year from now

	Method string `json:"method" gorm:"type:string;default:'credentials'"` // Authorization type (credentials, social, etc.)

	CreatedAt time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}

// BeforeCreate hook generates a UUID for the session ID before creation.
// This ensures cross-database compatibility (works with PostgreSQL, MySQL, MariaDB, and SQLite).
func (s *Session) BeforeCreate(tx *gorm.DB) error {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	return nil
}

// TableName specifies the table name for Session.
// Returns the configured table name from Authorization config, or default "sessions".
func (Session) TableName() string {
	tableNameRegistry.RLock()
	defer tableNameRegistry.RUnlock()
	return tableNameRegistry.sessionsTable
}

type User struct {
	// ID is the primary key. UUIDs are generated in BeforeCreate hook for cross-database compatibility.
	// For PostgreSQL: uses uuid type, for MySQL/SQLite: uses varchar(36) or text
	ID        string  `json:"id" gorm:"primaryKey;type:varchar(36)"`
	Username  *string `json:"username" gorm:"type:varchar(255)"`
	FirstName string  `json:"first_name" gorm:"type:varchar(255)"`
	LastName  string  `json:"last_name" gorm:"type:varchar(255)"`
	AvatarURL string  `json:"avatar_url" gorm:"type:text"`
	Email     string  `json:"email" gorm:"type:varchar(255)"`
	// Roles, Metadata, Options use text/json type for cross-database compatibility
	// PostgreSQL: jsonb, MySQL: json, SQLite: text
	// Defaults are handled in BeforeCreate hook for SQLite compatibility
	Roles    json.RawMessage `json:"roles" gorm:"type:text;not null"`
	Metadata json.RawMessage `json:"metadata" gorm:"type:text;not null"`
	Options  json.RawMessage `json:"options" gorm:"type:text;not null"`
	Password *string         `json:"password" gorm:"type:varchar(255)"`

	CreatedAt time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}

// BeforeCreate hook generates a UUID for the user ID before creation.
// This ensures cross-database compatibility (works with PostgreSQL, MySQL, MariaDB, and SQLite).
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == "" {
		u.ID = uuid.New().String()
	}
	// Set default empty JSON values if not set
	if len(u.Roles) == 0 {
		u.Roles = json.RawMessage(`[]`)
	}
	if len(u.Metadata) == 0 {
		u.Metadata = json.RawMessage(`{}`)
	}
	if len(u.Options) == 0 {
		u.Options = json.RawMessage(`{}`)
	}
	return nil
}

// TableName specifies the table name for User.
// Returns the configured table name from Authorization config, or default "users".
func (User) TableName() string {
	tableNameRegistry.RLock()
	defer tableNameRegistry.RUnlock()
	return tableNameRegistry.usersTable
}
