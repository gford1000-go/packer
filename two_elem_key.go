package packer

import (
	"errors"
	"fmt"
	"math/rand"

	"github.com/gford1000-go/serialise"
)

// Key is unique when compared across X and Y
type Key struct {
	X string
	Y string
}

var defaultLen uint8 = 16

// NewKeyCreator returns an IDCreator for type Key
func NewKeyCreator(size uint8) IDCreator[Key] {

	g := func() string { return createString(size) }

	return &keyGenerator{xg: g, yg: g}
}

// NewKeyCreatorFromKey leaves X unchanged, and adds a random suffix to Y
func NewKeyCreatorFromKey(key Key, size uint8) IDCreator[Key] {

	xg := func() string { return key.X }
	yg := func() string { return fmt.Sprintf("%s.%s", key.Y, createString(size)) }

	return &keyGenerator{xg: xg, yg: yg}
}

// newKeyForTesting returns an IDCreator with deterministic output - only use for testing
func newKeyCreatorForTesting(seed int64) IDCreator[Key] {

	g := func() string {
		r := rand.New(rand.NewSource(seed))

		b := []byte{}
		for range defaultLen {
			b = append(b, byte(r.Intn(256)))
		}
		return string(b)
	}

	k := &keyGenerator{}

	k.xg = g
	k.yg = g

	return k
}

type keyGenerator struct {
	xg func() string
	yg func() string
}

// ID returns a identifier with a low probability of non-uniqueness
func (k *keyGenerator) ID() Key {
	return Key{
		X: k.xg(),
		Y: k.yg(),
	}
}

// NewKeySerialiser returns an IDSerialiser for type Key.
// Utilitses V1 of the serialise MinDataApproach.
func NewKeySerialiser() (IDSerialiser[Key], error) {

	a := serialise.NewMinDataApproachWithVersion(serialise.V1) // Don't change or historic data is unrecoverable

	return &keySerialiser{
		a: a,
		n: "KeyV1",
	}, nil
}

type keySerialiser struct {
	n string
	a serialise.Approach
}

func (k *keySerialiser) Name() string {
	return k.n
}

func (k *keySerialiser) Pack(key Key) ([]byte, error) {
	b, _, err := serialise.ToBytes([]string{key.X, key.Y}, serialise.WithSerialisationApproach(k.a))
	return b, err
}

// ErrKeyDeserialisationError is raised when data does not deserialise to a Key instance
var ErrKeyDeserialisationError = errors.New("invalid data passed - cannot deserialise Key instance")

func (k *keySerialiser) Unpack(data []byte) (Key, error) {

	v, err := serialise.FromBytes(data, k.a)
	if err != nil {
		return Key{}, err
	}

	if d, ok := v.([]string); ok {
		if len(d) != 2 {
			return Key{}, ErrKeyDeserialisationError
		}

		return Key{X: d[0], Y: d[1]}, nil
	}

	return Key{}, ErrKeyDeserialisationError
}
