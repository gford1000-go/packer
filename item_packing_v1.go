package packer

import (
	c "crypto/rand"
	"errors"
	"math/big"
	"math/rand"

	"github.com/gford1000-go/serialise"
)

type itemPackingDetailsV1[T comparable] struct {
	key      T
	attrs    map[string]any
	params   *PackParams[T]
	opts     *Options
	elements []T
	attrMap  map[string][]string
	valMap   map[string][]byte
}

func (d *itemPackingDetailsV1[T]) pack(encryptedKey, encKey []byte) ([]byte, map[T]map[string][]byte, error) {

	if d.opts == nil {
		d.opts = &Options{}
	}
	if d.opts.serialiseOptions == nil {
		d.opts.serialiseOptions = []func(*serialise.Options){serialise.WithSerialisationApproach(d.params.Approach)}
	} else {
		d.opts.serialiseOptions = append(d.opts.serialiseOptions, serialise.WithSerialisationApproach(d.params.Approach))
	}

	err := d.createMaps()
	if err != nil {
		return nil, nil, err
	}

	return nil, nil, nil
}

func (d *itemPackingDetailsV1[T]) packElementsSlice() ([]byte, error) {

	eles := make([]any, len(d.elements))

	for i, ele := range d.elements {
		b, err := d.params.Packer.Pack(ele)
		if err != nil {
			return nil, err
		}
		eles[i] = b
	}

	b, _, err := serialise.ToBytesMany(eles, d.opts.serialiseOptions...)
	return b, err
}

var ErrInvalidDataToDeserialiseElements = errors.New("invalid data, cannot deserialise element slice")

func (d *itemPackingDetailsV1[T]) unpackElementsSlice(data []byte) error {

	v, err := serialise.FromBytesMany(data, d.params.Approach, d.opts.serialiseOptions...)
	if err != nil {
		return err
	}

	elements := make([]T, len(v))

	for i := 0; i < len(v); i++ {
		b, ok := v[i].([]byte)
		if !ok {
			return ErrInvalidDataToDeserialiseElements
		}

		t, err := d.params.Packer.Unpack(b)
		if err != nil {
			return err
		}

		elements[i] = t
	}

	d.elements = elements
	return nil
}

func (d *itemPackingDetailsV1[T]) createMaps() error {
	used := map[string]bool{}
	attrMap := map[string][]string{}
	valMap := map[string][]byte{}

	for k, v := range d.attrs {
		b, _, err := serialise.ToBytes(v, d.opts.serialiseOptions...)
		if err != nil {
			return err
		}

		// Where the serialised value exceedes the max size allowed, then
		// split it into chunks, each with its own unique attribute name.
		// attrMap then holds the array of attribute names in the correct
		// order to reconstruct the overall byte size when needed.
		attrMap[k] = []string{}
		for len(b) > int(d.opts.maxAttrValueSize) {
			an, err := d.uniqueAttributeName(used)
			if err != nil {
				return err
			}
			valMap[an] = b[0:d.opts.maxAttrValueSize]
			attrMap[k] = append(attrMap[k], an)
			b = b[d.opts.maxSize:]
		}
		an, err := d.uniqueAttributeName(used)
		if err != nil {
			return err
		}
		valMap[an] = b
		attrMap[k] = append(attrMap[k], an)
	}

	// Only store if all attributes serialised correctly
	d.attrMap = attrMap
	d.valMap = valMap
	return nil
}

// ErrUnableToCreateUniqueName raised if a unique attribute name cannot be determined before running out of retries
var ErrUnableToCreateUniqueName = errors.New("retries exceeded when creating random attribute names - increase the size of attribute names option")

func (d *itemPackingDetailsV1[T]) uniqueAttributeName(existing map[string]bool) (string, error) {

	mathRandOffset := func(n int) func() int {
		r := rand.New(rand.NewSource(d.opts.seed))
		return func() int {
			return r.Intn(n)
		}
	}

	cryptoRandOffset := func(n int) func() int {
		return func() int {
			i, err := c.Int(c.Reader, big.NewInt(int64(n)))
			if err != nil {
				panic(err)
			}
			return int(i.Int64())
		}
	}

	// Use a reduced selection so that attribute names are readable
	eles := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

	var randGen func() int
	if d.opts.seed != 0 {
		randGen = mathRandOffset(len(eles)) // Offer deterministic behaviour for testing only
	} else {
		randGen = cryptoRandOffset(len(eles))
	}

	// Ensure don't loop forever if set of attribute names is exhaused.  Shouldn't happen though.
	for i := 0; i < int(d.opts.attrNameRetries); i++ {
		var b = make([]byte, d.opts.attrNameSize)
		for j := 0; j < int(d.opts.attrNameSize); j++ {
			b[j] = eles[randGen()]
		}

		s := string(b)
		if _, ok := existing[s]; !ok {
			existing[s] = true
			return s, nil
		}
	}

	return "", ErrUnableToCreateUniqueName
}
