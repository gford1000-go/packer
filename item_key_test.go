package packer

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"
)

func TestNewEnvelopeKeyProvider(t *testing.T) {

	ki := &EnvelopeKeyProviderInfo{
		ID:  "ABC",
		Key: []byte("01234567890123450123456789012345"),
	}

	m := map[EnvelopeKeyID]EnvelopeKeyProvider{}

	finder := func(id EnvelopeKeyID) (EnvelopeKeyProvider, error) {
		if e, ok := m[id]; ok {
			return e, nil
		}
		return nil, errors.New("Boom!")
	}

	provider, err := NewEnvelopeKeyProvider(ki, finder)
	if err != nil {
		t.Fatalf("Unexpected error creating provider: %v", err)
	}

	keys := map[string]bool{}

	for i := 0; i < 100000; i++ {

		enc, key, err := provider.New()
		if err != nil {
			t.Fatalf("Unexpected error creating new key: %v", err)
		}

		key2, err := provider.Decrypt(enc)
		if err != nil {
			t.Fatalf("Unexpected error decrypting key: %v", err)
		}

		if !bytes.Equal(key, key2) {
			t.Fatal("Unexpected difference in keys")
		}

		if _, ok := keys[string(key)]; ok {
			t.Fatal("Created duplicate keys")
		}
		keys[string(key)] = true
	}
}

func TestNewEnvelopeKeyProvider_1(t *testing.T) {

	m := map[EnvelopeKeyID]EnvelopeKeyProvider{}

	finder := func(id EnvelopeKeyID) (EnvelopeKeyProvider, error) {
		if e, ok := m[id]; ok {
			return e, nil
		}
		return nil, errors.New("Boom!")
	}

	info := []EnvelopeKeyProviderInfo{}

	for i := 0; i < 100; i++ {
		b := make([]byte, 12)
		rand.Reader.Read(b)

		key := make([]byte, 2*aes.BlockSize)
		rand.Reader.Read(key)

		info = append(info, EnvelopeKeyProviderInfo{
			ID:  EnvelopeKeyID(string(b)),
			Key: key,
		})
	}

	providers := make([]EnvelopeKeyProvider, len(info))

	for i, ki := range info {
		provider, _ := NewEnvelopeKeyProvider(&ki, finder)
		m[provider.ID()] = provider
		providers[i] = provider
	}

	keys := map[string]bool{}

	chooseProvider := func() EnvelopeKeyProvider {
		bi, _ := rand.Int(rand.Reader, big.NewInt(int64(len(providers))))
		return providers[bi.Int64()]
	}

	chooseSecondProvider := func(otherID EnvelopeKeyID) EnvelopeKeyProvider {
		for {
			provider := chooseProvider()
			if provider.ID() != otherID {
				return provider
			}
		}
	}

	// Verify that the finder logic is working correctly;
	// i.e. that an encrypted key can be decrypted by an invocation to a
	// different provider, provided the original provider is in the finder
	// it has available.

	for i := 0; i < 100000; i++ {

		provider := chooseProvider()

		enc, key, err := provider.New()
		if err != nil {
			t.Fatalf("Unexpected error creating new key: %v", err)
		}

		key2, err := chooseSecondProvider(provider.ID()).Decrypt(enc)
		if err != nil {
			t.Fatalf("Unexpected error decrypting key: %v", err)
		}

		if !bytes.Equal(key, key2) {
			t.Fatal("Unexpected difference in keys")
		}

		if _, ok := keys[string(key)]; ok {
			t.Fatal("Created duplicate keys")
		}
		keys[string(key)] = true
	}
}
