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
	packer       IDSerialiser[T]
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
			v, err := serialise.FromBytesMany(b, e.approach, serialise.WithAESGCMEncryption(key))
			if err != nil {
				return nil, err
			}
			switch len(v) {
			case 0:
				return nil, ErrInvalidDataToUnpack
			case 1:
				m[attr] = v[0]
			case 2:
				flag, ok := v[0].(bool)
				if !ok {
					return nil, ErrInvalidDataToUnpack
				}
				b, ok := v[1].([]byte)
				if !ok {
					return nil, ErrInvalidDataToUnpack
				}
				t, err := e.packer.Unpack(b)
				if err != nil {
					return nil, ErrInvalidDataToUnpack
				}
				if flag {
					m[attr] = t
				} else {
					m[attr] = &t
				}
			default:
				flag, ok := v[0].(bool)
				if !ok {
					return nil, ErrInvalidDataToUnpack
				}
				size, ok := v[1].(int64)
				if !ok {
					return nil, ErrInvalidDataToUnpack
				}

				if flag {
					tt := make([]T, size)
					var i int64
					for i = 0; i < size; i++ {
						b, ok := v[i+2].([]byte)
						if !ok {
							return nil, ErrInvalidDataToUnpack
						}
						tt[i], err = e.packer.Unpack(b)
						if err != nil {
							return nil, ErrInvalidDataToUnpack
						}
					}
					m[attr] = tt
				} else {
					tt := make([]*T, size)
					var i int64
					for i = 0; i < size; i++ {
						b, ok := v[i+2].([]byte)
						if !ok {
							return nil, ErrInvalidDataToUnpack
						}
						t, err := e.packer.Unpack(b)
						if err != nil {
							return nil, ErrInvalidDataToUnpack
						}
						tt[i] = &t
					}
					m[attr] = tt
				}
			}
		}
	}

	return m, nil
}
