package social

import (
	"context"
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"
)

// GormStorage implements StorageInterface for GORM database.
//
// Debug Mode:
// The GormStorage supports debug mode which provides detailed logging of all operations.
// To enable debug mode:
//  1. Use NewGormStorageWithDebug(conn, true) when creating the storage
//  2. Or use SetDebug(true) on an existing storage instance
//  3. Or set Debug: true in SocialDataConfig when creating SocialData
//
// Debug mode will log:
//   - All Get/Set/Delete operations with keys and values
//   - Success/failure status of operations
//   - Database connection events
//   - Storage statistics (via GetStats method)
//
// Example usage:
//
//	config := &SocialDataConfig{
//	    SQLStorage: db,
//	    Debug: true,
//	}
//	socialData := New(config)
//
//	// Or enable debug mode after creation:
//	socialData.SetDebug(true)
//
//	// Get storage statistics (only available in debug mode):
//	stats, err := socialData.GetStorageStats()
type GormStorage struct {
	db    *gorm.DB
	debug bool
}

// StorageItem represents a storage item in the database.
type StorageItem struct {
	Key       string    `gorm:"primaryKey;type:varchar(255)"`
	Value     []byte    `gorm:"type:bytea"`
	ExpiresAt time.Time `gorm:"index"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}

// TableName specifies the table name for StorageItem.
func (StorageItem) TableName() string {
	return "storage_items"
}

// NewGormStorage creates a new GORM storage instance.
func NewGormStorage(conn *gorm.DB) StorageInterface {
	if conn == nil {
		return nil
	}

	// Auto-migrate the storage table
	if err := conn.AutoMigrate(&StorageItem{}); err != nil {
		return nil
	}

	return &GormStorage{db: conn, debug: false}
}

// NewGormStorageWithDebug creates a new GORM storage instance with debug mode enabled.
func NewGormStorageWithDebug(conn *gorm.DB, debug bool) StorageInterface {
	if conn == nil {
		return nil
	}

	// Auto-migrate the storage table
	if err := conn.AutoMigrate(&StorageItem{}); err != nil {
		return nil
	}

	return &GormStorage{db: conn, debug: debug}
}

// SetDebug enables or disables debug mode.
func (s *GormStorage) SetDebug(debug bool) {
	s.debug = debug
}

// IsDebug returns whether debug mode is enabled.
func (s *GormStorage) IsDebug() bool {
	return s.debug
}

// debugLog logs debug messages if debug mode is enabled.
func (s *GormStorage) debugLog(format string, args ...interface{}) {
	if s.debug {
		log.Printf("[GORM_STORAGE_DEBUG] "+format, args...)
	}
}

// Get retrieves a value by key using the default context.
func (s *GormStorage) Get(key string) ([]byte, error) {
	return s.GetWithContext(context.Background(), key)
}

// GetWithContext retrieves a value by key using the provided context.
func (s *GormStorage) GetWithContext(ctx context.Context, key string) ([]byte, error) {
	if !isValidKey(key) {
		s.debugLog("Get: invalid key provided: %s", key)
		return nil, nil
	}

	s.debugLog("Get: retrieving key: %s", key)

	var item StorageItem
	err := s.db.WithContext(ctx).
		Where("key = ? AND (expires_at IS NULL OR expires_at > ?)", key, time.Now()).
		First(&item).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			s.debugLog("Get: key not found: %s", key)
			return nil, nil
		}
		s.debugLog("Get: error retrieving key %s: %v", key, err)
		return nil, err
	}

	s.debugLog("Get: successfully retrieved key: %s, value length: %d", key, len(item.Value))
	return item.Value, nil
}

// Set stores a value with the given key and expiration duration using the default context.
func (s *GormStorage) Set(key string, val []byte, exp time.Duration) error {
	return s.SetWithContext(context.Background(), key, val, exp)
}

// SetWithContext stores a value with the given key and expiration duration using the provided context.
func (s *GormStorage) SetWithContext(ctx context.Context, key string, val []byte, exp time.Duration) error {
	if !isValidKey(key) || !isValidValue(val) {
		s.debugLog("Set: invalid key or value provided - key: %s, value length: %d", key, len(val))
		return nil
	}

	expiresAt := time.Time{}
	if exp > 0 {
		expiresAt = time.Now().Add(exp)
	}

	item := StorageItem{
		Key:       key,
		Value:     val,
		ExpiresAt: expiresAt,
	}

	s.debugLog("Set: storing key: %s, value length: %d, expires at: %v", key, len(val), expiresAt)

	err := s.db.WithContext(ctx).Save(&item).Error
	if err != nil {
		s.debugLog("Set: error storing key %s: %v", key, err)
	} else {
		s.debugLog("Set: successfully stored key: %s", key)
	}

	return err
}

// Delete removes a value by key using the default context.
func (s *GormStorage) Delete(key string) error {
	return s.DeleteWithContext(context.Background(), key)
}

// DeleteWithContext removes a value by key using the provided context.
func (s *GormStorage) DeleteWithContext(ctx context.Context, key string) error {
	if !isValidKey(key) {
		s.debugLog("Delete: invalid key provided: %s", key)
		return nil
	}

	s.debugLog("Delete: removing key: %s", key)

	err := s.db.WithContext(ctx).Where("key = ?", key).Delete(&StorageItem{}).Error
	if err != nil {
		s.debugLog("Delete: error removing key %s: %v", key, err)
	} else {
		s.debugLog("Delete: successfully removed key: %s", key)
	}

	return err
}

// Reset removes all stored values using the default context.
func (s *GormStorage) Reset() error {
	return s.ResetWithContext(context.Background())
}

// ResetWithContext removes all stored values using the provided context.
func (s *GormStorage) ResetWithContext(ctx context.Context) error {
	s.debugLog("Reset: removing all stored values")

	err := s.db.WithContext(ctx).Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&StorageItem{}).Error
	if err != nil {
		s.debugLog("Reset: error removing all values: %v", err)
	} else {
		s.debugLog("Reset: successfully removed all values")
	}

	return err
}

// Keys returns all stored keys using the default context.
func (s *GormStorage) Keys() ([][]byte, error) {
	return s.KeysWithContext(context.Background())
}

// KeysWithContext returns all stored keys using the provided context.
func (s *GormStorage) KeysWithContext(ctx context.Context) ([][]byte, error) {
	s.debugLog("Keys: retrieving all keys")

	var items []StorageItem
	err := s.db.WithContext(ctx).
		Where("expires_at IS NULL OR expires_at > ?", time.Now()).
		Find(&items).Error
	if err != nil {
		s.debugLog("Keys: error retrieving keys: %v", err)
		return nil, err
	}

	keys := make([][]byte, len(items))
	for i, item := range items {
		keys[i] = []byte(item.Key)
	}

	s.debugLog("Keys: successfully retrieved %d keys", len(keys))
	return keys, nil
}

// Close closes the GORM database connection.
func (s *GormStorage) Close() error {
	s.debugLog("Close: closing database connection")

	sqlDB, err := s.db.DB()
	if err != nil {
		s.debugLog("Close: error getting underlying DB: %v", err)
		return err
	}

	err = sqlDB.Close()
	if err != nil {
		s.debugLog("Close: error closing database: %v", err)
	} else {
		s.debugLog("Close: successfully closed database connection")
	}

	return err
}

// Conn returns the underlying GORM database client.
func (s *GormStorage) Conn() *gorm.DB {
	return s.db
}

// GetStats returns storage statistics for debugging purposes.
func (s *GormStorage) GetStats() (map[string]interface{}, error) {
	if !s.debug {
		return nil, fmt.Errorf("debug mode must be enabled to get stats")
	}

	stats := make(map[string]interface{})

	// Count total items
	var totalCount int64
	if err := s.db.Model(&StorageItem{}).Count(&totalCount).Error; err != nil {
		return nil, err
	}
	stats["total_items"] = totalCount

	// Count expired items
	var expiredCount int64
	if err := s.db.Model(&StorageItem{}).Where("expires_at IS NOT NULL AND expires_at <= ?", time.Now()).Count(&expiredCount).Error; err != nil {
		return nil, err
	}
	stats["expired_items"] = expiredCount

	// Count active items
	var activeCount int64
	if err := s.db.Model(&StorageItem{}).Where("expires_at IS NULL OR expires_at > ?", time.Now()).Count(&activeCount).Error; err != nil {
		return nil, err
	}
	stats["active_items"] = activeCount

	s.debugLog("GetStats: retrieved stats - total: %d, expired: %d, active: %d", totalCount, expiredCount, activeCount)

	return stats, nil
}
