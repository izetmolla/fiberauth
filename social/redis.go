package social

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisStorage implements StorageInterface for Redis.
type RedisStorage struct {
	db redis.UniversalClient
}

// NewRedisStorage creates a new Redis storage instance.
func NewRedisStorage(conn redis.UniversalClient) StorageInterface {
	if conn == nil {
		return nil
	}
	return &RedisStorage{db: conn}
}

// Get retrieves a value by key using the default context.
func (s *RedisStorage) Get(key string) ([]byte, error) {
	return s.GetWithContext(context.Background(), key)
}

// GetWithContext retrieves a value by key using the provided context.
func (s *RedisStorage) GetWithContext(ctx context.Context, key string) ([]byte, error) {
	if !isValidKey(key) {
		return nil, nil
	}

	val, err := s.db.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	return val, err
}

// Set stores a value with the given key and expiration duration using the default context.
func (s *RedisStorage) Set(key string, val []byte, exp time.Duration) error {
	return s.SetWithContext(context.Background(), key, val, exp)
}

// SetWithContext stores a value with the given key and expiration duration using the provided context.
func (s *RedisStorage) SetWithContext(ctx context.Context, key string, val []byte, exp time.Duration) error {
	if !isValidKey(key) || !isValidValue(val) {
		return nil
	}
	return s.db.Set(ctx, key, val, exp).Err()
}

// Delete removes a value by key using the default context.
func (s *RedisStorage) Delete(key string) error {
	return s.DeleteWithContext(context.Background(), key)
}

// DeleteWithContext removes a value by key using the provided context.
func (s *RedisStorage) DeleteWithContext(ctx context.Context, key string) error {
	if !isValidKey(key) {
		return nil
	}
	return s.db.Del(ctx, key).Err()
}

// Reset removes all stored values using the default context.
func (s *RedisStorage) Reset() error {
	return s.ResetWithContext(context.Background())
}

// ResetWithContext removes all stored values using the provided context.
func (s *RedisStorage) ResetWithContext(ctx context.Context) error {
	return s.db.FlushDB(ctx).Err()
}

// Keys returns all stored keys using the default context.
func (s *RedisStorage) Keys() ([][]byte, error) {
	return s.KeysWithContext(context.Background())
}

// KeysWithContext returns all stored keys using the provided context.
func (s *RedisStorage) KeysWithContext(ctx context.Context) ([][]byte, error) {
	var keys [][]byte
	var cursor uint64
	var err error

	for {
		var batch []string
		batch, cursor, err = s.db.Scan(ctx, cursor, "*", 10).Result()
		if err != nil {
			return nil, err
		}

		for _, key := range batch {
			keys = append(keys, []byte(key))
		}

		if cursor == 0 {
			break
		}
	}

	return keys, nil
}

// Close closes the Redis connection.
func (s *RedisStorage) Close() error {
	return s.db.Close()
}

// Conn returns the underlying Redis client.
func (s *RedisStorage) Conn() redis.UniversalClient {
	return s.db
}
