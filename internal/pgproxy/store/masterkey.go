package store

import "errors"

var (
	// ErrMasterKeyMissing means the registry holds encrypted data but the key
	// file is gone. A new key must not be generated: it could never decrypt the
	// existing data.
	ErrMasterKeyMissing = errors.New("master key file is missing but the registry holds data encrypted with it")
	// ErrMasterKeyWrong means the key file does not match the registry.
	ErrMasterKeyWrong = errors.New("master key file does not match this registry")
)
