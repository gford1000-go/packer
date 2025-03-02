package packer

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"

	"github.com/gford1000-go/serialise"
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

	for i := 0; i < 10000; i++ {

		enc, key, err := provider.New()
		if err != nil {
			t.Fatalf("Unexpected error creating new key: %v", err)
		}

		key2, err := provider.Decrypt(context.TODO(), enc)
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

	for i := 0; i < 10000; i++ {

		provider := chooseProvider()

		enc, key, err := provider.New()
		if err != nil {
			t.Fatalf("Unexpected error creating new key: %v", err)
		}

		key2, err := chooseSecondProvider(provider.ID()).Decrypt(context.TODO(), enc)
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

func TestNewEnvelopeKeyProvider_2(t *testing.T) {
	p, err := NewEnvelopeKeyProvider(nil, nil)
	if err == nil {
		t.Fatal("Unexpected success when expected error")
	}
	if !errors.Is(err, ErrMissingEnvelopeKeyProviderInfo) {
		t.Fatalf("Unexpected error: expected: %v, got: %v", ErrMissingEnvelopeKeyProviderInfo, err)
	}
	if p != nil {
		t.Fatal("Expected nil provider, but got instance")
	}
}

func TestNewEnvelopeKeyProvider_3(t *testing.T) {
	ki := &EnvelopeKeyProviderInfo{}
	p, err := NewEnvelopeKeyProvider(ki, nil)
	if err == nil {
		t.Fatal("Unexpected success when expected error")
	}
	if !errors.Is(err, ErrProviderMustHaveAnID) {
		t.Fatalf("Unexpected error: expected: %v, got: %v", ErrProviderMustHaveAnID, err)
	}
	if p != nil {
		t.Fatal("Expected nil provider, but got instance")
	}
}

func TestNewEnvelopeKeyProvider_4(t *testing.T) {
	ki := &EnvelopeKeyProviderInfo{
		ID: "anID",
	}
	p, err := NewEnvelopeKeyProvider(ki, nil)
	if err == nil {
		t.Fatal("Unexpected success when expected error")
	}
	if !errors.Is(err, ErrProviderMustHaveKey) {
		t.Fatalf("Unexpected error: expected: %v, got: %v", ErrProviderMustHaveKey, err)
	}
	if p != nil {
		t.Fatal("Expected nil provider, but got instance")
	}
}

func TestNewEnvelopeKeyProvider_5(t *testing.T) {
	ki := &EnvelopeKeyProviderInfo{
		ID:  "anID",
		Key: []byte("01234567890123456789012345678901"),
	}
	p, err := NewEnvelopeKeyProvider(ki, nil)
	if err == nil {
		t.Fatal("Unexpected success when expected error")
	}
	if !errors.Is(err, ErrMissingFinder) {
		t.Fatalf("Unexpected error: expected: %v, got: %v", ErrMissingFinder, err)
	}
	if p != nil {
		t.Fatal("Expected nil provider, but got instance")
	}
}

func TestNewEnvelopeKeyProvider_6(t *testing.T) {
	ki := &EnvelopeKeyProviderInfo{
		ID:  "anID",
		Key: []byte("01234567890123456789012345678901"),
	}

	finder := func(EnvelopeKeyID) (EnvelopeKeyProvider, error) {
		return nil, errors.New("unknown ID")
	}

	p, err := NewEnvelopeKeyProvider(ki, finder)
	if err != nil {
		t.Fatalf("Unexpected failure when expected success: %v", err)
	}
	if p == nil {
		t.Fatal("Expected provider instance, but got nil")
	}
}

func TestNewEnvelopeKeyProvider_Decrypt(t *testing.T) {
	ki := &EnvelopeKeyProviderInfo{
		ID:  "anID",
		Key: []byte("01234567890123456789012345678901"),
	}

	finder := func(EnvelopeKeyID) (EnvelopeKeyProvider, error) {
		return nil, errors.New("unknown ID")
	}

	p, err := NewEnvelopeKeyProvider(ki, finder)
	if err != nil {
		t.Fatalf("Unexpected failure when expected success: %v", err)
	}

	b, err := p.Decrypt(context.TODO(), nil)
	if err == nil {
		t.Fatal("Unexpected success when expected error")
	}
	if b != nil {
		t.Fatal("Unexpected instance returned when expected nil")
	}
}

func TestNewEnvelopeKeyProvider_Decrypt_1(t *testing.T) {
	ki := &EnvelopeKeyProviderInfo{
		ID:  "anID",
		Key: []byte("01234567890123456789012345678901"),
	}

	finder := func(EnvelopeKeyID) (EnvelopeKeyProvider, error) {
		return nil, errors.New("unknown ID")
	}

	p, err := NewEnvelopeKeyProvider(ki, finder)
	if err != nil {
		t.Fatalf("Unexpected failure when expected success: %v", err)
	}

	b, err := p.Decrypt(context.TODO(), []byte{})
	if err == nil {
		t.Fatal("Unexpected success when expected error")
	}
	if b != nil {
		t.Fatal("Unexpected instance returned when expected nil")
	}
}

func TestNewEnvelopeKeyProvider_Decrypt_2(t *testing.T) {
	ki := &EnvelopeKeyProviderInfo{
		ID:  "anID",
		Key: []byte("01234567890123456789012345678901"),
	}

	finder := func(EnvelopeKeyID) (EnvelopeKeyProvider, error) {
		return nil, errors.New("unknown ID")
	}

	p, err := NewEnvelopeKeyProvider(ki, finder)
	if err != nil {
		t.Fatalf("Unexpected failure when expected success: %v", err)
	}

	// Pass invalid []byte to Decrypt
	b, _, err := serialise.ToBytes(string("oops"), serialise.WithSerialisationApproach(serialise.NewMinDataApproachWithVersion(serialise.V1)))
	if err != nil {
		t.Fatalf("Unexpected failure when expected success: %v", err)
	}

	b, err = p.Decrypt(context.TODO(), b)
	if err == nil {
		t.Fatal("Unexpected success when expected error")
	}
	if b != nil {
		t.Fatal("Unexpected instance returned when expected nil")
	}
}

func TestNewEnvelopeKeyProvider_Decrypt_3(t *testing.T) {
	ki := &EnvelopeKeyProviderInfo{
		ID:  "anID",
		Key: []byte("01234567890123456789012345678901"),
	}

	errID := errors.New("unknown ID")

	finder := func(EnvelopeKeyID) (EnvelopeKeyProvider, error) {
		return nil, errID
	}

	p, err := NewEnvelopeKeyProvider(ki, finder)
	if err != nil {
		t.Fatalf("Unexpected failure when expected success: %v", err)
	}

	ep, ok := p.(*evKeyProvider)
	if !ok {
		t.Fatalf("Unexpected cast error: %T", p)
	}
	b, err := ep.enc([]byte("bad key"))
	if err != nil {
		t.Fatalf("Unexpected failure when expected success: %v", err)
	}

	// Hand-crafted encrypted key fails to deserialise - will generate one of two errors
	b, err = p.Decrypt(context.TODO(), b)
	if err == nil {
		t.Fatal("Unexpected success when expected error")
	}
	if !(errors.Is(err, serialise.ErrMinDataTypeNotDeserialisable) || errors.Is(err, serialise.ErrFromBytesInvalidData)) {
		t.Fatalf("Unexpected error: expected either: '%v' or '%v', got: %v", serialise.ErrMinDataTypeNotDeserialisable, serialise.ErrFromBytesInvalidData, err)
	}
	if b != nil {
		t.Fatal("Unexpected instance returned when expected nil")
	}
}

func TestNewEnvelopeKeyProvider_Decrypt_4(t *testing.T) {
	ki := &EnvelopeKeyProviderInfo{
		ID:  "anID",
		Key: []byte("01234567890123456789012345678901"),
	}

	errID := errors.New("unknown ID")

	finder := func(EnvelopeKeyID) (EnvelopeKeyProvider, error) {
		return nil, errID
	}

	p, err := NewEnvelopeKeyProvider(ki, finder)
	if err != nil {
		t.Fatalf("Unexpected failure when expected success: %v", err)
	}

	ep, ok := p.(*evKeyProvider)
	if !ok {
		t.Fatalf("Unexpected cast error: %T", p)
	}
	b, err := ep.enc([]byte("bad key"))
	if err != nil {
		t.Fatalf("Unexpected failure when expected success: %v", err)
	}
	b, _, err = serialise.ToBytesMany(
		[]any{
			string("badID"),
			b,
		}, serialise.WithSerialisationApproach(serialise.NewMinDataApproachWithVersion(serialise.V1)))
	if err != nil {
		t.Fatalf("Unexpected failure when expected success: %v", err)
	}

	// Unknown ID error should be raised
	b, err = p.Decrypt(context.TODO(), b)
	if err == nil {
		t.Fatal("Unexpected success when expected error")
	}
	if !errors.Is(err, errID) {
		t.Fatalf("Unexpected error: expected: %v, got: %v", errID, err)
	}
	if b != nil {
		t.Fatal("Unexpected instance returned when expected nil")
	}
}
