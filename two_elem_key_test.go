package packer

import "testing"

func TestNewKeyForTesting(t *testing.T) {

	a := newKeyCreatorForTesting(42)
	b := newKeyCreatorForTesting(42)

	for i := 0; i < 10000; i++ {
		kA := a.ID()
		kB := b.ID()

		if kA != kB {
			t.Fatalf("Expected identifical key generation, but differs: %v, %v", kA, kB)
		}
	}
}

func TestNewKey(t *testing.T) {

	a := NewKeyCreator()
	b := NewKeyCreator()

	m := map[Key]bool{}

	for i := 0; i < 100000; i++ {
		kA := a.ID()
		kB := b.ID()

		if kA == kB {
			t.Fatalf("Expected unique key generation, but same: %v, %v", kA, kB)
		}

		if _, ok := m[kA]; ok {
			t.Fatalf("Repeated key generation detected - very surprising!")
		}

		m[kA] = true
	}
}

func TestNewKeySerialiser(t *testing.T) {

	a := NewKeyCreator()
	k := a.ID()

	s, err := NewKeySerialiser()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	b, err := s.Pack(k)
	if err != nil {
		t.Fatalf("Unexpected error packing key %v: %v", k, err)
	}

	k1, err := s.Unpack(b)
	if err != nil {
		t.Fatalf("Unexpected error unpacking key %v: %v", k, err)
	}

	if k != k1 {
		t.Fatalf("Expected identifical keys, but differ: %v, %v", k, k1)
	}
}
