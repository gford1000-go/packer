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

type testHandler interface {
	Fatalf(string, ...any)
}

func testCreateEnv(t testHandler) (func(item *Item[Key]) ([]byte, DataLoader[Key], error), func(data []byte, dataLoader DataLoader[Key]) (*EncryptedItem[Key], error), EnvelopeKeyProvider) {
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

	testPack := func(item *Item[Key]) ([]byte, DataLoader[Key], error) {

		pParams := &PackParams[Key]{
			Provider: provider,
			Creator:  NewKeyCreator(),
			Packer:   serialiser,
			Approach: serialise.NewMinDataApproachWithVersion(serialise.V1),
		}

		info, data, err := Pack[Key](item, pParams)
		if err != nil {
			return nil, nil, err
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

		return info, dataLoader, nil
	}

	testUnpack := func(data []byte, dataLoader DataLoader[Key]) (*EncryptedItem[Key], error) {

		uParams := &UnpackParams[Key]{
			IDRetriever: idRetriever,
			Provider:    provider,
			DataLoader:  dataLoader,
		}

		eItem, err := Unpack(context.TODO(), data, uParams)
		if err != nil {
			return nil, err
		}

		return eItem, nil
	}

	return testPack, testUnpack, provider
}

func TestPack_1(t *testing.T) {
	info, itemData, err := Pack[Key](nil, nil)
	if err == nil {
		t.Fatal("Unexpected success when expected error")
	}
	if !errors.Is(err, ErrPackNoAttributes) {
		t.Fatalf("Unexpected error: expected: %v, got: %v", ErrPackNoAttributes, err)
	}
	if info != nil {
		t.Fatal("Expected nil info, but received instance")
	}
	if itemData != nil {
		t.Fatal("Expected nil itemData, but received instance")
	}
}

func TestPack_2(t *testing.T) {
	item := &Item[Key]{}
	info, itemData, err := Pack[Key](item, nil)
	if err == nil {
		t.Fatal("Unexpected success when expected error")
	}
	if !errors.Is(err, ErrPackNoAttributes) {
		t.Fatalf("Unexpected error: expected: %v, got: %v", ErrPackNoAttributes, err)
	}
	if info != nil {
		t.Fatal("Expected nil info, but received instance")
	}
	if itemData != nil {
		t.Fatal("Expected nil itemData, but received instance")
	}
}

func TestPack_3(t *testing.T) {
	item := &Item[Key]{
		Key: Key{X: "A", Y: "B"},
	}
	info, itemData, err := Pack(item, nil)
	if err == nil {
		t.Fatal("Unexpected success when expected error")
	}
	if !errors.Is(err, ErrPackNoAttributes) {
		t.Fatalf("Unexpected error: expected: %v, got: %v", ErrPackNoAttributes, err)
	}
	if info != nil {
		t.Fatal("Expected nil info, but received instance")
	}
	if itemData != nil {
		t.Fatal("Expected nil itemData, but received instance")
	}
}

func TestPack_4(t *testing.T) {
	item := &Item[Key]{
		Key: Key{X: "A", Y: "B"},
		Attributes: map[string]any{
			"Answer": int64(42),
		},
	}
	info, itemData, err := Pack(item, nil)
	if err == nil {
		t.Fatal("Unexpected success when expected error")
	}
	if !errors.Is(err, ErrPackNoParams) {
		t.Fatalf("Unexpected error: expected: %v, got: %v", ErrPackNoParams, err)
	}
	if info != nil {
		t.Fatal("Expected nil info, but received instance")
	}
	if itemData != nil {
		t.Fatal("Expected nil itemData, but received instance")
	}
}

func TestPack_5(t *testing.T) {
	item := &Item[Key]{
		Key: Key{X: "A", Y: "B"},
		Attributes: map[string]any{
			"Answer": int64(42),
		},
	}
	params := &PackParams[Key]{}
	info, itemData, err := Pack(item, params)
	if err == nil {
		t.Fatal("Unexpected success when expected error")
	}
	if !errors.Is(err, ErrParamsNoProvider) {
		t.Fatalf("Unexpected error: expected: %v, got: %v", ErrParamsNoProvider, err)
	}
	if info != nil {
		t.Fatal("Expected nil info, but received instance")
	}
	if itemData != nil {
		t.Fatal("Expected nil itemData, but received instance")
	}
}

func TestPack_6(t *testing.T) {
	item := &Item[Key]{
		Key: Key{X: "A", Y: "B"},
		Attributes: map[string]any{
			"Answer": int64(42),
		},
	}

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

	params := &PackParams[Key]{
		Provider: getProvider(),
	}
	info, itemData, err := Pack(item, params)
	if err == nil {
		t.Fatal("Unexpected success when expected error")
	}
	if !errors.Is(err, ErrParamsNoIDCreator) {
		t.Fatalf("Unexpected error: expected: %v, got: %v", ErrParamsNoIDCreator, err)
	}
	if info != nil {
		t.Fatal("Expected nil info, but received instance")
	}
	if itemData != nil {
		t.Fatal("Expected nil itemData, but received instance")
	}
}

func TestPack_7(t *testing.T) {
	item := &Item[Key]{
		Key: Key{X: "A", Y: "B"},
		Attributes: map[string]any{
			"Answer": int64(42),
		},
	}

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

	params := &PackParams[Key]{
		Provider: getProvider(),
		Creator:  NewKeyCreator(),
	}
	info, itemData, err := Pack(item, params)
	if err == nil {
		t.Fatal("Unexpected success when expected error")
	}
	if !errors.Is(err, ErrParamsNoIDSerialiser) {
		t.Fatalf("Unexpected error: expected: %v, got: %v", ErrParamsNoIDSerialiser, err)
	}
	if info != nil {
		t.Fatal("Expected nil info, but received instance")
	}
	if itemData != nil {
		t.Fatal("Expected nil itemData, but received instance")
	}
}

func TestPack_8(t *testing.T) {
	item := &Item[Key]{
		Key: Key{X: "A", Y: "B"},
		Attributes: map[string]any{
			"Answer": int64(42),
		},
	}

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

	serialiser, _ := NewKeySerialiser()

	params := &PackParams[Key]{
		Provider: getProvider(),
		Creator:  NewKeyCreator(),
		Packer:   serialiser,
	}
	info, itemData, err := Pack(item, params)
	if err == nil {
		t.Fatal("Unexpected success when expected error")
	}
	if !errors.Is(err, ErrParamsNoApproach) {
		t.Fatalf("Unexpected error: expected: %v, got: %v", ErrParamsNoApproach, err)
	}
	if info != nil {
		t.Fatal("Expected nil info, but received instance")
	}
	if itemData != nil {
		t.Fatal("Expected nil itemData, but received instance")
	}
}

func TestPack_9(t *testing.T) {
	item := &Item[Key]{
		Key: Key{X: "A", Y: "B"},
		Attributes: map[string]any{
			"Answer": int64(42),
		},
	}

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

	serialiser, _ := NewKeySerialiser()

	params := &PackParams[Key]{
		Provider: getProvider(),
		Creator:  NewKeyCreator(),
		Packer:   serialiser,
		Approach: serialise.Default(),
	}
	info, itemData, err := Pack(item, params)
	if err != nil {
		t.Fatalf("Unexpected error when expected success: %v", err)
	}
	if info == nil {
		t.Fatal("Expected info, but received nil")
	}
	if itemData == nil {
		t.Fatal("Expected itemData, but received nil")
	}
}

func TestPack_10(t *testing.T) {
	item := &Item[Key]{
		Key: Key{X: "A", Y: "B"},
		Attributes: map[string]any{
			"Answer": int64(42),
			"Life":   string("Hello World"),
		},
	}

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

	serialiser, _ := NewKeySerialiser()

	params := &PackParams[Key]{
		Provider: getProvider(),
		Creator:  NewKeyCreator(),
		Packer:   serialiser,
		Approach: serialise.Default(),
	}
	info, itemData, err := Pack(item, params)
	if err != nil {
		t.Fatalf("Unexpected error when expected success: %v", err)
	}
	if info == nil {
		t.Fatal("Expected info, but received nil")
	}
	if itemData == nil {
		t.Fatal("Expected itemData, but received nil")
	}
}

func TestPack(t *testing.T) {

	tests := []*Item[Key]{
		{
			Key: Key{X: "A", Y: "B"},
			Attributes: map[string]any{
				"aaa": int8(10),
			},
		},
		{
			Key: Key{X: "A", Y: "B"},
			Attributes: map[string]any{
				"aaa": int64(42),
				"bbb": []string{"Hello", "World"},
			},
		},
		{
			Key: Key{X: "A", Y: "B"},
			Attributes: map[string]any{
				"ref": Key{X: "C", Y: "D"},
			},
		},
		{
			Key: Key{X: "A", Y: "B"},
			Attributes: map[string]any{
				"ref": &Key{X: "C", Y: "D"},
			},
		},
		{
			Key: Key{X: "A", Y: "B"},
			Attributes: map[string]any{
				"ref": []Key{Key{X: "C", Y: "D"}},
			},
		},
	}

	testPack, testUnpack, provider := testCreateEnv(t)

	for i, input := range tests {

		b, l, err := testPack(input)
		if err != nil {
			t.Fatalf("(%d) Error packing input: %v", i, err)
		}

		output, err := testUnpack(b, l)
		if err != nil {
			t.Fatalf("(%d) Error unpacking input: %v", i, err)
		}

		if input.Key != output.GetKey() {
			t.Fatalf("(%d) Mismatch in keys: expected: %s, got: %s", i, input.Key, output.GetKey())
		}

		for k, v := range input.Attributes {
			m, err := output.GetValues(context.TODO(), []string{k}, provider)
			if err != nil {
				t.Fatalf("(%d) Unexpected error during value retrieval: %v", i, err)
			}
			v1, ok := m[k]
			if !ok {
				t.Fatalf("(%d) Unexpected failure to retrieve attribute %s", i, k)
			}
			compareValue(v1, v, fmt.Sprintf("%T", v), t)
		}
	}
}

func BenchmarkPack(b *testing.B) {
	packer, _, _ := testCreateEnv(b)

	item := &Item[Key]{
		Key: Key{X: "A", Y: "B"},
		Attributes: map[string]any{
			"aaa": int8(10),
		},
	}

	for i := 0; i < b.N; i++ {
		_, _, err := packer(item)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
	}
}

func BenchmarkUnpack(b *testing.B) {
	packer, unpacker, _ := testCreateEnv(b)

	item := &Item[Key]{
		Key: Key{X: "A", Y: "B"},
		Attributes: map[string]any{
			"aaa": int8(10),
		},
	}

	data, loader, err := packer(item)
	if err != nil {
		b.Fatalf("Unexpected error: %v", err)
	}

	for i := 0; i < b.N; i++ {
		_, err := unpacker(data, loader)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
	}
}

func BenchmarkUnpack_1(b *testing.B) {
	packer, unpacker, _ := testCreateEnv(b)

	item := &Item[Key]{
		Key: Key{X: "A", Y: "B"},
		Attributes: map[string]any{
			"first name": string("Fred"),
			"last name":  string("Flintstone"),
			"dob":        time.Date(2000, 1, 1, 12, 43, 30, 0, time.Local),
			"title":      "Mr",
			"profession": "Actor",
		},
	}

	data, loader, err := packer(item)
	if err != nil {
		b.Fatalf("Unexpected error: %v", err)
	}

	for i := 0; i < b.N; i++ {
		_, err := unpacker(data, loader)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
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
		t.Fatalf("Unexpected error: b was the wrong type: %T (a: %T)", b, a)
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
	case Key:
		testCompareValue[Key](a, b, name, t)
	case *Key:
		testComparePtrValue[Key](a, b, name, t)
	case []Key:
		testCompareSliceValue[Key](a, b, name, t)
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
