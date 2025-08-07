package social

// isValidKey checks if the key is valid.
func isValidKey(key string) bool {
	return len(key) > 0
}

// isValidValue checks if the value is valid.
func isValidValue(val []byte) bool {
	return len(val) > 0
}
