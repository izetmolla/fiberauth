package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SetSessionsTableName sets the table name for Session model.
// This is called during initialization to support custom table names.
func SetSessionsTableName(name string) {
	if name == "" {
		name = "sessions"
	}
	tableNameRegistry.Lock()
	defer tableNameRegistry.Unlock()
	tableNameRegistry.sessionsTable = name
}

// GetSessionsTableName returns the current Session table name.
func GetSessionsTableName() string {
	tableNameRegistry.RLock()
	defer tableNameRegistry.RUnlock()
	return tableNameRegistry.sessionsTable
}

// Session represents a user session in the system.
// Designed for cross-database compatibility (PostgreSQL, MySQL, MariaDB, SQLite).
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
