// Package database provides database operations for authentication.
// This package handles database queries and migrations, isolated from other concerns.
package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/izetmolla/fiberauth/pkg/storage/models"
	"gorm.io/gorm"
)

// Manager handles database operations for authentication.
type Manager struct {
	db               *gorm.DB
	usersTableName   string
	sessionTableName string
}

// NewManager creates a new database manager instance.
//
// Parameters:
//   - db: GORM database instance
//   - usersTable: Custom table name for users (empty string uses default "users")
//   - sessionTable: Custom table name for sessions (empty string uses default "sessions")
//
// Returns:
//   - *Manager: Database manager instance
func NewManager(db *gorm.DB, usersTable, sessionTable string) *Manager {
	if usersTable == "" {
		usersTable = "users"
	}
	if sessionTable == "" {
		sessionTable = "sessions"
	}

	return &Manager{
		db:               db,
		usersTableName:   usersTable,
		sessionTableName: sessionTable,
	}
}

// GetDB returns the underlying GORM database instance.
func (m *Manager) GetDB() *gorm.DB {
	return m.db
}

// AutoMigrate checks if tables exist and creates them if they don't.
// Uses the table names specified in the manager configuration.
//
// Returns:
//   - error: Error if migration fails
func (m *Manager) AutoMigrate() error {
	if m.db == nil {
		return fmt.Errorf("database client is not initialized")
	}

	// Check if users table exists by table name
	userTableExists := m.db.Migrator().HasTable(m.usersTableName)
	if !userTableExists {
		// Create users table with custom table name
		if err := m.db.Table(m.usersTableName).AutoMigrate(&models.User{}); err != nil {
			return fmt.Errorf("failed to create users table '%s': %w", m.usersTableName, err)
		}
	} else {
		// Table exists, but we still need to migrate schema changes
		if err := m.db.Table(m.usersTableName).AutoMigrate(&models.User{}); err != nil {
			return fmt.Errorf("failed to migrate users table '%s': %w", m.usersTableName, err)
		}
	}

	// Check if sessions table exists by table name
	sessionTableExists := m.db.Migrator().HasTable(m.sessionTableName)
	if !sessionTableExists {
		// Create sessions table with custom table name
		if err := m.db.Table(m.sessionTableName).AutoMigrate(&models.Session{}); err != nil {
			return fmt.Errorf("failed to create sessions table '%s': %w", m.sessionTableName, err)
		}
	} else {
		// Table exists, but we still need to migrate schema changes
		if err := m.db.Table(m.sessionTableName).AutoMigrate(&models.Session{}); err != nil {
			return fmt.Errorf("failed to migrate sessions table '%s': %w", m.sessionTableName, err)
		}
	}

	return nil
}

// FindUserByID finds a user by their ID.
//
// Parameters:
//   - id: The user ID to search for
//
// Returns:
//   - *models.User: The found user
//   - error: Error if user not found or database error occurs
func (m *Manager) FindUserByID(id any) (*models.User, error) {
	var user models.User
	err := m.db.Table(m.usersTableName).Where("id = ? AND deleted_at IS NULL", id).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return &user, nil
}

// FindUserByEmail finds a user by email or username.
//
// Parameters:
//   - email: The email address to search for
//   - username: The username to search for (optional)
//
// Returns:
//   - *models.User: The found user
//   - error: Error if user not found or database error occurs
func (m *Manager) FindUserByEmail(email string, username string) (*models.User, error) {
	var user models.User
	query := m.db.Table(m.usersTableName)

	if email != "" {
		// Simple check: if email contains @, treat as email, otherwise username
		if containsAt(email) {
			query = query.Where("email = ? AND deleted_at IS NULL", email)
		} else {
			query = query.Where("username = ? AND deleted_at IS NULL", email)
		}
	} else if username != "" {
		query = query.Where("username = ? AND deleted_at IS NULL", username)
	} else {
		return nil, errors.New("email or username is required")
	}

	err := query.First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return &user, nil
}

// CreateUser creates a new user in the database.
//
// Parameters:
//   - user: The user to create
//
// Returns:
//   - error: Error if user creation fails
func (m *Manager) CreateUser(user *models.User) error {
	return m.db.Table(m.usersTableName).Create(user).Error
}

// GetSessionByID retrieves a session by ID from the database.
//
// Parameters:
//   - sessionID: The session ID to retrieve
//   - nowTime: Current time for expiration checks
//
// Returns:
//   - *models.Session: The session if found
//   - error: Error if session not found or database error occurs
func (m *Manager) GetSessionByID(sessionID string, nowTime time.Time) (*models.Session, error) {
	var session models.Session
	query := m.db.Table(m.sessionTableName).
		Where("id = ? AND expires_at > ? AND deleted_at IS NULL", sessionID, nowTime).
		First(&session)

	if query.Error != nil {
		if errors.Is(query.Error, gorm.ErrRecordNotFound) {
			return nil, errors.New("session not found")
		}
		return nil, query.Error
	}

	return &session, nil
}

// GetUserByID retrieves user data by ID for session.
//
// Parameters:
//   - userID: The user ID to retrieve
//
// Returns:
//   - roles, metadata, options: JSON raw messages from user
//   - error: Error if database error occurs (not if user not found)
func (m *Manager) GetUserByID(userID string) (roles, metadata, options json.RawMessage, err error) {
	var user models.User
	userQuery := m.db.Table(m.usersTableName).
		Where("id = ? AND deleted_at IS NULL", userID).
		Select("roles, metadata, options").
		First(&user)

	// Use default empty values if user not found (LEFT JOIN behavior)
	if userQuery.Error != nil {
		if !errors.Is(userQuery.Error, gorm.ErrRecordNotFound) {
			// If it's a real error (not just not found), return it
			return nil, nil, nil, userQuery.Error
		}
		// User not found - use defaults
		roles = json.RawMessage(`[]`)
		metadata = json.RawMessage(`{}`)
		options = json.RawMessage(`{}`)
		return roles, metadata, options, nil
	}

	roles = user.Roles
	metadata = user.Metadata
	options = user.Options

	// Ensure non-empty values (handle NULL from database)
	if len(roles) == 0 {
		roles = json.RawMessage(`[]`)
	}
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}
	if len(options) == 0 {
		options = json.RawMessage(`{}`)
	}

	return roles, metadata, options, nil
}

// CreateSession creates a new session in the database.
//
// Parameters:
//   - session: The session to create
//
// Returns:
//   - error: Error if session creation fails
func (m *Manager) CreateSession(session *models.Session) error {
	return m.db.Table(m.sessionTableName).Create(session).Error
}

// containsAt checks if a string contains the @ character.
func containsAt(s string) bool {
	for _, c := range s {
		if c == '@' {
			return true
		}
	}
	return false
}
