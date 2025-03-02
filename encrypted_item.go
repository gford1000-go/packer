package packer

import (
	"context"
	"sync"

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

	if len(attrs) == 0 {
		return map[string]any{}, nil
	}

	if provider == nil {
		return nil, ErrProviderIsNil
	}

	key, err := provider.Decrypt(ctx, e.encryptedKey)
	if err != nil {
		return nil, err
	}

	m := map[string]any{}

	type resp struct {
		a string
		v any
		e error
	}

	c := make(chan *resp, len(attrs))
	defer close(c)

	var wg sync.WaitGroup

	for i := range attrs {
		wg.Add(1)

		go func(attr string) {
			defer wg.Done()

			resp := &resp{a: attr}
			defer func() { c <- resp }()

			b, ok := e.attributes[attr]
			if !ok {
				return
			}

			v, err := serialise.FromBytesMany(b, e.approach, serialise.WithAESGCMEncryption(key))
			if err != nil {
				resp.e = err
				return
			}
			switch len(v) {
			case 0:
				resp.e = ErrInvalidDataToUnpack
				return
			case 1:
				resp.v = v[0]
				return
			case 2:
				flag, ok := v[0].(bool)
				if !ok {
					resp.e = ErrInvalidDataToUnpack
					return
				}
				b, ok := v[1].([]byte)
				if !ok {
					resp.e = ErrInvalidDataToUnpack
					return
				}
				t, err := e.packer.Unpack(b)
				if err != nil {
					resp.e = ErrInvalidDataToUnpack
					return
				}
				if flag {
					resp.v = t
					return
				} else {
					resp.v = &t
					return
				}
			default:
				flag, ok := v[0].(bool)
				if !ok {
					resp.e = ErrInvalidDataToUnpack
					return
				}
				size, ok := v[1].(int64)
				if !ok {
					resp.e = ErrInvalidDataToUnpack
					return
				}

				if flag {
					tt := make([]T, size)
					for i := range size {
						b, ok := v[i+2].([]byte)
						if !ok {
							resp.e = ErrInvalidDataToUnpack
							return
						}
						tt[i], err = e.packer.Unpack(b)
						if err != nil {
							resp.e = ErrInvalidDataToUnpack
							return
						}
					}
					resp.v = tt
					return
				} else {
					tt := make([]*T, size)
					for i := range size {
						b, ok := v[i+2].([]byte)
						if !ok {
							resp.e = ErrInvalidDataToUnpack
							return
						}
						t, err := e.packer.Unpack(b)
						if err != nil {
							resp.e = ErrInvalidDataToUnpack
							return
						}
						tt[i] = &t
					}
					resp.v = tt
					return
				}
			}
		}(attrs[i])
	}

	wg.Wait()

	for range len(attrs) {
		resp := <-c
		if resp.e != nil {
			return nil, resp.e
		}
		if resp.v != nil {
			m[resp.a] = resp.v
		}
	}

	return m, nil
}
