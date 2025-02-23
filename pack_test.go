package packer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/gford1000-go/serialise"
)

func TestPack(t *testing.T) {

	getProvider := func() EnvelopeKeyProvider {
		ki := &EnvelopeKeyProviderInfo{
			ID:  "Key1",
			Key: []byte("01234567890123456789012345678912"),
		}
		m := map[EnvelopeKeyID]EnvelopeKeyProvider{}

		finder := func(id EnvelopeKeyID) (EnvelopeKeyProvider, error) {
			provider, ok := m[id]
			if !ok {
				return nil, errors.New("unknown provider id")
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

	serialiser, err := NewKeySerialiser()
	if err != nil {
		t.Fatalf("Unexpected error preparing Key serialiser: %v", err)
	}

	idRetriever := func(name string) (IDSerialiser[Key], error) {
		return serialiser, nil
	}

	testPack := func(item *Item[Key]) ([]byte, DataLoader[Key]) {

		pParams := &PackParams[Key]{
			Provider: provider,
			Creator:  NewKeyCreator(),
			Packer:   serialiser,
			Approach: serialise.NewMinDataApproachWithVersion(serialise.V1),
		}

		info, data, err := Pack[Key](item, pParams)
		if err != nil {
			t.Fatalf("Unexpected error during packing: %v", err)
		}

		dataLoader := func(ctx context.Context, keys []Key) (map[string][]byte, error) {

			attrs := map[string][]byte{}

			for _, key := range keys {
				if m, ok := data[key]; ok {
					for k, v := range m {
						attrs[k] = v
					}
				}
			}

			return attrs, nil
		}

		return info, dataLoader
	}

	testUnpack := func(data []byte, dataLoader DataLoader[Key]) *EncryptedItem[Key] {

		uParams := &UnpackParams[Key]{
			IDRetriever: idRetriever,
			Provider:    provider,
			DataLoader:  dataLoader,
		}

		eItem, err := Unpack(context.TODO(), data, uParams)
		if err != nil {
			t.Fatalf("Unexpected error during unpacking: %v", err)
		}

		return eItem
	}

	input := &Item[Key]{
		Key: Key{X: "A", Y: "B"},
		Attributes: map[string]any{
			"aaa": int64(42),
			"bbb": []string{"Hello", "World"},
		},
	}

	output := testUnpack(testPack(input))

	if input.Key != output.GetKey() {
		t.Fatalf("Mismatch in keys: expected: %s, got: %s", input.Key, output.GetKey())
	}

	for k, v := range input.Attributes {
		m, err := output.GetValues(context.TODO(), []string{k}, provider)
		if err != nil {
			t.Fatalf("Unexpected error during value retrieval: %v", err)
		}
		v1, ok := m[k]
		if !ok {
			t.Fatalf("Unexpected failure to retrieve attribute %s", k)
		}
		compareValue(v1, v, fmt.Sprintf("%T", v), t)
	}
}

// ---------------------------------
// Value comparison helper functions
// ---------------------------------

func timeNeq(x any, y any) (time.Time, bool, bool) {
	switch v := x.(type) {
	case time.Time:
		return v, v != (y.(time.Time)).Truncate(0), false
	default:
		return *new(time.Time), false, true
	}
}

func testCompareValue[T comparable](a, b any, name string, t *testing.T, opts ...func(any, any) (T, bool, bool)) {

	neq := func(x any, y any) (T, bool, bool) {
		if xx, ok := x.(T); ok {
			return xx, xx != y.(T), false
		}
		return *new(T), false, true
	}

	if len(opts) > 0 {
		neq = opts[0]
	}

	switch v := b.(type) {
	case T:
		if aa, test, bad := neq(a, v); test {
			t.Fatalf("Data mismatch: expected %v, got: %v", v, aa)
		} else if bad {
			t.Fatalf("Type mismatch: expected: %s, got: %s", name, fmt.Sprintf("%T", a))
		}
	default:
		t.Fatalf("Unexpected error: b was the wrong type: %s", fmt.Sprintf("%T", b))
	}
}

func testCompareSliceValue[T comparable](a, b any, name string, t *testing.T) {
	switch v := b.(type) {
	case []T:
		if aa, ok := a.([]T); ok {
			if len(aa) != len(v) {
				t.Fatalf("Data size mismatch: expected %v, got: %v", len(v), len(aa))
			}
			for i, vv := range aa {
				if v[i] != vv {
					t.Fatalf("Data mismatch at %d: expected %v, got: %v", i, vv, aa)
				}
			}
		} else {
			t.Fatalf("Type mismatch: expected: %s, got: %s", name, fmt.Sprintf("%T", a))
		}
	default:
		t.Fatalf("Unexpected error: b was the wrong type: %s", fmt.Sprintf("%T", b))
	}
}

func testComparePtrValue[T comparable](a, b any, name string, t *testing.T) {

	switch v := b.(type) {
	case *T:
		if aa, ok := a.(*T); ok {
			if (aa == nil && v != nil) || (aa != nil && v == nil) {
				t.Fatalf("Pointer mismatch: expected %v, got: %v", v, aa)
			}
			if *aa != *v {
				t.Fatalf("Data mismatch: expected %v, got: %v", *v, *aa)
			}
		} else {
			t.Fatalf("Type mismatch: expected: %s, got: %s", name, fmt.Sprintf("%T", a))
		}
	default:
		t.Fatalf("Unexpected error: b was the wrong type: %s", fmt.Sprintf("%T", b))
	}
}

func compareValue(a, b any, name string, t *testing.T) {
	if b == nil {
		if a != nil {
			t.Fatalf("Mismatch in <nil>")
		}
		return
	}

	switch v := b.(type) {
	case []byte:
		testCompareSliceValue[byte](a, b, name, t)
	case int8:
		testCompareValue[int8](a, b, name, t)
	case *int8:
		testComparePtrValue[int8](a, b, name, t)
	case []int8:
		testCompareSliceValue[int8](a, b, name, t)
	case int16:
		testCompareValue[int16](a, b, name, t)
	case *int16:
		testComparePtrValue[int16](a, b, name, t)
	case []int16:
		testCompareSliceValue[int16](a, b, name, t)
	case int32:
		testCompareValue[int32](a, b, name, t)
	case *int32:
		testComparePtrValue[int32](a, b, name, t)
	case []int32:
		testCompareSliceValue[int32](a, b, name, t)
	case int64:
		testCompareValue[int64](a, b, name, t)
	case *int64:
		testComparePtrValue[int64](a, b, name, t)
	case []int64:
		testCompareSliceValue[int64](a, b, name, t)
	case uint8:
		testCompareValue[uint8](a, b, name, t)
	case *uint8:
		testComparePtrValue[uint8](a, b, name, t)
	case uint16:
		testCompareValue[uint16](a, b, name, t)
	case *uint16:
		testComparePtrValue[uint16](a, b, name, t)
	case []uint16:
		testCompareSliceValue[uint16](a, b, name, t)
	case uint32:
		testCompareValue[uint32](a, b, name, t)
	case *uint32:
		testComparePtrValue[uint32](a, b, name, t)
	case []uint32:
		testCompareSliceValue[uint32](a, b, name, t)
	case uint64:
		testCompareValue[uint64](a, b, name, t)
	case *uint64:
		testComparePtrValue[uint64](a, b, name, t)
	case []uint64:
		testCompareSliceValue[uint64](a, b, name, t)
	case float32:
		testCompareValue[float32](a, b, name, t)
	case *float32:
		testComparePtrValue[float32](a, b, name, t)
	case []float32:
		testCompareSliceValue[float32](a, b, name, t)
	case float64:
		testCompareValue[float64](a, b, name, t)
	case *float64:
		testComparePtrValue[float64](a, b, name, t)
	case []float64:
		testCompareSliceValue[float64](a, b, name, t)
	case bool:
		testCompareValue[bool](a, b, name, t)
	case *bool:
		testComparePtrValue[bool](a, b, name, t)
	case []bool:
		testCompareSliceValue[bool](a, b, name, t)
	case time.Duration:
		testCompareValue[time.Duration](a, b, name, t)
	case *time.Duration:
		testComparePtrValue[time.Duration](a, b, name, t)
	case []time.Duration:
		testCompareSliceValue[time.Duration](a, b, name, t)
	case time.Time:
		testCompareValue[time.Time](a, b, name, t, timeNeq)
	case string:
		testCompareValue[string](a, b, name, t)
	case *string:
		testComparePtrValue[string](a, b, name, t)
	case []string:
		testCompareSliceValue[string](a, b, name, t)
	case [][]uint8:
		bb := b.([][]uint8)
		if len(bb) != len(v) {
			t.Fatalf("Mismatch in lengths: %d vs %d for %s", len(bb), len(v), fmt.Sprintf("%T", b))
		}
		for i := 0; i < len(v); i++ {
			if !bytes.Equal([]byte(bb[i]), []byte(v[i])) {
				t.Fatalf("Mismatch in values: (%v) vs (%v) for item %d, %s", bb[i], v[i], i, fmt.Sprintf("%T", b))
			}
		}
	default:
		t.Fatalf("No test available for type: %s (%s)", fmt.Sprintf("%T", b), name)
	}

}
