package packer

import (
	"context"
	"errors"
	"testing"
)

func TestEncryptedItem_GetValues(t *testing.T) {

	packer, unpacker, provider := testCreateEnv(t)

	attrName := "meaningOfLife"
	attrValue := int8(42)

	item := &Item[Key]{
		Key: Key{X: "A", Y: "B"},
		Attributes: map[string]any{
			attrName: attrValue,
		},
	}

	b, loader, err := packer(item)
	if err != nil {
		t.Fatalf("Unexpected error during pack: %v", err)
	}

	e, err := unpacker(b, loader)
	if err != nil {
		t.Fatalf("Unexpected error during unpack: %v", err)
	}
	if e == nil {
		t.Fatal("Expected instance, got nil")
	}

	m, err := e.GetValues(context.TODO(), []string{attrName}, provider)
	if err != nil {
		t.Fatalf("Unexpected error during GetValues: %v", err)
	}
	if len(m) != 1 {
		t.Fatal("Expected instance, got nil")
	}

	if m[attrName].(int8) != item.Attributes[attrName].(int8) {
		t.Fatal("Unexpected mismatch in attribute values")
	}
}

func TestEncryptedItem_GetValues_1(t *testing.T) {

	packer, unpacker, _ := testCreateEnv(t)

	attrName := "meaningOfLife"
	attrValue := int8(42)

	item := &Item[Key]{
		Key: Key{X: "A", Y: "B"},
		Attributes: map[string]any{
			attrName: attrValue,
		},
	}

	b, loader, err := packer(item)
	if err != nil {
		t.Fatalf("Unexpected error during pack: %v", err)
	}

	e, err := unpacker(b, loader)
	if err != nil {
		t.Fatalf("Unexpected error during unpack: %v", err)
	}
	if e == nil {
		t.Fatal("Expected instance, got nil")
	}

	// Missing provider
	m, err := e.GetValues(context.TODO(), []string{attrName}, nil)
	if err == nil {
		t.Fatal("Unexpected success when expecting error")
	}
	if !errors.Is(err, ErrProviderIsNil) {
		t.Fatalf("Unexpected error: expected: %v, got: %v", ErrProviderIsNil, err)

	}
	if m != nil {
		t.Fatal("Unexpected instance returned when expecting nil")
	}

}

func TestEncryptedItem_GetValues_2(t *testing.T) {

	packer, unpacker, _ := testCreateEnv(t)

	attrName := "meaningOfLife"
	attrValue := int8(42)

	item := &Item[Key]{
		Key: Key{X: "A", Y: "B"},
		Attributes: map[string]any{
			attrName: attrValue,
		},
	}

	b, loader, err := packer(item)
	if err != nil {
		t.Fatalf("Unexpected error during pack: %v", err)
	}

	e, err := unpacker(b, loader)
	if err != nil {
		t.Fatalf("Unexpected error during unpack: %v", err)
	}
	if e == nil {
		t.Fatal("Expected instance, got nil")
	}

	errUnknownID := errors.New("unknown provider id")

	getProvider := func() EnvelopeKeyProvider {
		ki := &EnvelopeKeyProviderInfo{
			ID:  "anotherID",
			Key: []byte("12345678901234567890123456789012"),
		}
		m := map[EnvelopeKeyID]EnvelopeKeyProvider{}

		finder := func(id EnvelopeKeyID) (EnvelopeKeyProvider, error) {
			provider, ok := m[id]
			if !ok {
				return nil, errUnknownID
			}
			return provider, nil
		}

		provider, err := NewEnvelopeKeyProvider(ki, finder)
		if err != nil {
			t.Fatalf("Unexpected error preparing provider: %v", err)
		}
		m[provider.ID()] = provider

		return provider
	}

	provider := getProvider()

	// Different provider without access to the key
	m, err := e.GetValues(context.TODO(), []string{attrName}, provider)
	if err == nil {
		t.Fatal("Unexpected success when expecting error")
	}
	if !errors.Is(err, errUnknownID) {
		t.Fatalf("Unexpected error: expected: %v, got: %v", errUnknownID, err)

	}
	if m != nil {
		t.Fatal("Unexpected instance returned when expecting nil")
	}

}

func TestEncryptedItem_GetValues_4(t *testing.T) {

	packer, unpacker, _ := testCreateEnv(t)

	attrName := "meaningOfLife"
	attrValue := int8(42)

	item := &Item[Key]{
		Key: Key{X: "A", Y: "B"},
		Attributes: map[string]any{
			attrName: attrValue,
		},
	}

	b, loader, err := packer(item)
	if err != nil {
		t.Fatalf("Unexpected error during pack: %v", err)
	}

	e, err := unpacker(b, loader)
	if err != nil {
		t.Fatalf("Unexpected error during unpack: %v", err)
	}
	if e == nil {
		t.Fatal("Expected instance, got nil")
	}

	errUnknownID := errors.New("unknown provider id")

	getProvider := func() EnvelopeKeyProvider {
		ki := &EnvelopeKeyProviderInfo{
			ID:  "Key1",
			Key: []byte("01234567890123456789012345678912"),
		}
		m := map[EnvelopeKeyID]EnvelopeKeyProvider{}

		finder := func(id EnvelopeKeyID) (EnvelopeKeyProvider, error) {
			provider, ok := m[id]
			if !ok {
				return nil, errUnknownID
			}
			return provider, nil
		}

		provider, err := NewEnvelopeKeyProvider(ki, finder)
		if err != nil {
			t.Fatalf("Unexpected error preparing provider: %v", err)
		}
		m[provider.ID()] = provider

		return provider
	}

	provider := getProvider()

	// Different provider but WITH access to the key - should be successful
	m, err := e.GetValues(context.TODO(), []string{attrName}, provider)
	if err != nil {
		t.Fatalf("Unexpected error when expecting success: %v", err)
	}
	if len(m) != 1 {
		t.Fatal("Expected instance, got nil")
	}

	if m[attrName].(int8) != item.Attributes[attrName].(int8) {
		t.Fatal("Unexpected mismatch in attribute values")
	}
}
