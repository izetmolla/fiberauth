package fiberauth

import (
	"time"

	"github.com/izetmolla/fiberauth/pkg/storage/database"
)

// FindUserByID returns a user using a custom model type.
func FindUserByID[T any](a *Authorization, id any) (*T, error) {
	return database.FindUserByIDAs[T](a.dbManager.GetDB(), a.usersModelTable, id)
}

// FindUserByEmail returns a user by email or username using a custom model type.
func FindUserByEmail[T any](a *Authorization, email string, username string) (*T, error) {
	return database.FindUserByEmailAs[T](a.dbManager.GetDB(), a.usersModelTable, email, username)
}

// CreateUser creates a user using a custom model type.
func CreateUser[T any](a *Authorization, user *T) error {
	return database.CreateUserAs[T](a.dbManager.GetDB(), a.usersModelTable, user)
}

// GetSessionByID returns a session using a custom model type.
func GetSessionByID[T any](a *Authorization, sessionID string, nowTime time.Time) (*T, error) {
	return database.GetSessionByIDAs[T](a.dbManager.GetDB(), a.sessionModelTable, sessionID, nowTime)
}

// CreateSession creates a session using a custom model type.
func CreateSession[T any](a *Authorization, session *T) error {
	return database.CreateSessionAs[T](a.dbManager.GetDB(), a.sessionModelTable, session)
}
