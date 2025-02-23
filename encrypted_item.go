package packer

import (
	"context"

	"github.com/gford1000-go/serialise"
)

// EncryptedItem is a partially deserialised format, with the attribute values
// remaining encrypted until required
type EncryptedItem[T comparable] struct {
	key          T
	attributes   map[string][]byte
	encryptedKey []byte
	approach     serialise.Approach
}

// GetKey returns the key of this EncryptedItem
func (e *EncryptedItem[T]) GetKey() T {
	return e.key
}

// GetValues will attempt to decrypt and return the requested attributes using the provider.
// Any attributes that are not included in this EncryptedItem are ignored.
// Context is provided so that the caller details may be included and passed to the provider to verify access.  This is
// an implementation detail of the EnvelopeKeyProvider; no access checks are performed in GetValues.
func (e *EncryptedItem[T]) GetValues(ctx context.Context, attrs []string, provider EnvelopeKeyProvider) (map[string]any, error) {

	key, err := provider.Decrypt(ctx, e.encryptedKey)
	if err != nil {
		return nil, err
	}

	m := map[string]any{}

	for _, attr := range attrs {
		if b, ok := e.attributes[attr]; ok {
			v, err := serialise.FromBytes(b, e.approach, serialise.WithAESGCMEncryption(key))
			if err != nil {
				return nil, err
			}

			m[attr] = v
		}
	}

	return m, nil
}
