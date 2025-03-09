package packer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
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
			Creator:  NewKeyCreator(defaultLen),
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
		Creator:  NewKeyCreator(defaultLen),
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
		Creator:  NewKeyCreator(defaultLen),
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
		Creator:  NewKeyCreator(defaultLen),
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
		Creator:  NewKeyCreator(defaultLen),
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
				"ref": []Key{{X: "C", Y: "D"}},
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

func TestPack_11(t *testing.T) {

	nattrs := 1000

	item := &Item[Key]{
		Key:        Key{X: "A", Y: "B"},
		Attributes: make(map[string]any, nattrs),
	}

	ls := strings.Repeat("Hello World;", 100000)

	for i := range nattrs {
		item.Attributes[fmt.Sprintf("%d", i)] = ls
	}

	testPack, testUnpack, provider := testCreateEnv(t)

	b, l, err := testPack(item)
	if err != nil {
		t.Fatalf("Error packing input: %v", err)
	}

	output, err := testUnpack(b, l)
	if err != nil {
		t.Fatalf("Error unpacking input: %v", err)
	}

	if item.Key != output.GetKey() {
		t.Fatalf("Mismatch in keys: expected: %s, got: %s", item.Key, output.GetKey())
	}

	for k, v := range item.Attributes {
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

func TestUnpack_1(t *testing.T) {

	item, err := Unpack[Key](context.TODO(), nil, nil)

	if err == nil {
		t.Fatal("Unexpected success when expected error")
	}
	if !errors.Is(err, ErrUnpackNoData) {
		t.Fatalf("Unexpected error: expected: %v, got: %v", ErrUnpackNoData, err)
	}
	if item != nil {
		t.Fatal("Expected item is nil, but is instance")
	}
}

func TestUnpack_2(t *testing.T) {
	packer, _, _ := testCreateEnv(t)

	item := &Item[Key]{
		Key: Key{X: "A", Y: "B"},
		Attributes: map[string]any{
			"aaa": int8(10),
		},
	}

	data, _, err := packer(item)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	i, err := Unpack[Key](context.TODO(), data, nil)

	if err == nil {
		t.Fatal("Unexpected success when expected error")
	}
	if !errors.Is(err, ErrUnpackNoParams) {
		t.Fatalf("Unexpected error: expected: %v, got: %v", ErrUnpackNoParams, err)
	}
	if i != nil {
		t.Fatal("Expected item is nil, but is instance")
	}

}

func TestUnpack_3(t *testing.T) {
	packer, _, _ := testCreateEnv(t)

	item := &Item[Key]{
		Key: Key{X: "A", Y: "B"},
		Attributes: map[string]any{
			"aaa": int8(10),
		},
	}

	data, _, err := packer(item)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	params := &UnpackParams[Key]{}

	i, err := Unpack(context.TODO(), data, params)

	if err == nil {
		t.Fatal("Unexpected success when expected error")
	}
	if !errors.Is(err, ErrDataLoaderIsNil) {
		t.Fatalf("Unexpected error: expected: %v, got: %v", ErrDataLoaderIsNil, err)
	}
	if i != nil {
		t.Fatal("Expected item is nil, but is instance")
	}

}

func TestUnpack_4(t *testing.T) {
	packer, _, _ := testCreateEnv(t)

	item := &Item[Key]{
		Key: Key{X: "A", Y: "B"},
		Attributes: map[string]any{
			"aaa": int8(10),
		},
	}

	data, loader, err := packer(item)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	params := &UnpackParams[Key]{
		DataLoader: loader,
	}

	i, err := Unpack(context.TODO(), data, params)

	if err == nil {
		t.Fatal("Unexpected success when expected error")
	}
	if !errors.Is(err, ErrIDRetrieverIsNil) {
		t.Fatalf("Unexpected error: expected: %v, got: %v", ErrIDRetrieverIsNil, err)
	}
	if i != nil {
		t.Fatal("Expected item is nil, but is instance")
	}

}

func TestUnpack_5(t *testing.T) {
	packer, _, _ := testCreateEnv(t)

	item := &Item[Key]{
		Key: Key{X: "A", Y: "B"},
		Attributes: map[string]any{
			"aaa": int8(10),
		},
	}

	data, loader, err := packer(item)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	serialiser, err := NewKeySerialiser()
	if err != nil {
		t.Fatalf("Unexpected error preparing Key serialiser: %v", err)
	}

	idRetriever := func(name string) (IDSerialiser[Key], error) {
		return serialiser, nil
	}

	params := &UnpackParams[Key]{
		DataLoader:  loader,
		IDRetriever: idRetriever,
	}

	i, err := Unpack(context.TODO(), data, params)

	if err == nil {
		t.Fatal("Unexpected success when expected error")
	}
	if !errors.Is(err, ErrProviderIsNil) {
		t.Fatalf("Unexpected error: expected: %v, got: %v", ErrProviderIsNil, err)
	}
	if i != nil {
		t.Fatal("Expected item is nil, but is instance")
	}

}

func TestUnpack_6(t *testing.T) {
	packer, _, provider := testCreateEnv(t)

	item := &Item[Key]{
		Key: Key{X: "A", Y: "B"},
		Attributes: map[string]any{
			"aaa": int8(10),
		},
	}

	data, loader, err := packer(item)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	serialiser, err := NewKeySerialiser()
	if err != nil {
		t.Fatalf("Unexpected error preparing Key serialiser: %v", err)
	}

	idRetriever := func(name string) (IDSerialiser[Key], error) {
		return serialiser, nil
	}

	params := &UnpackParams[Key]{
		DataLoader:  loader,
		IDRetriever: idRetriever,
		Provider:    provider,
	}

	i, err := Unpack(context.TODO(), data, params)

	if err != nil {
		t.Fatal("Unexpected error when expected success", err)
	}
	if i == nil {
		t.Fatal("Expected item is instance, but got nil")
	}

	if i.GetKey() != item.Key {
		t.Fatalf("Key mismatch: expected: %v, got: %v", item.Key, i.GetKey())
	}

	m, err := i.GetValues(context.TODO(), []string{"aaa"}, nil)

	if err == nil {
		t.Fatal("Unexpected success when expecting error whilst getting values")
	}
	if !errors.Is(err, ErrProviderIsNil) {
		t.Fatalf("Unexpected error: expected: %v, got: %v", ErrProviderIsNil, err)
	}
	if m != nil {
		t.Fatal("Expected nil map to be returned, but got instance")
	}

	if i.GetKey() != item.Key {
		t.Fatalf("Key mismatch: expected: %v, got: %v", item.Key, i.GetKey())
	}

	m, err = i.GetValues(context.TODO(), []string{"aaa"}, provider)

	if err != nil {
		t.Fatalf("Unexpected error when expecting success whilst getting values: %v", err)
	}
	if m == nil {
		t.Fatal("Unexpected nil map returned, when expecting instance")
	}

	aaav, ok := m["aaa"]
	if !ok {
		t.Fatal("Unexpected value for 'aaa' to be returned, but not found")
	}
	if aaav.(int8) != int8(10) {
		t.Fatalf("Unexpected value for 'aaa', expected: %v, got: %v", int8(10), aaav)
	}

	m, err = i.GetValues(context.TODO(), []string{"bbb"}, provider)

	if err != nil {
		t.Fatalf("Unexpected error when expecting success whilst getting values: %v", err)
	}
	if m == nil {
		t.Fatal("Unexpected nil map returned, when expecting instance")
	}
	if len(m) > 0 {
		t.Fatalf("Unexpected map returned, expected empty, but got: %v", m)
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

func BenchmarkEncryptedItem_GetValues(b *testing.B) {
	packer, unpacker, provider := testCreateEnv(b)

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

	ei, err := unpacker(data, loader)
	if err != nil {
		b.Fatalf("Unexpected error: %v", err)
	}

	ctx := context.TODO()

	for i := 0; i < b.N; i++ {
		_, err := ei.GetValues(ctx, []string{"first name", "last name", "dob"}, provider)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
	}
}

var longStr = strings.Repeat("Hello World;", 10000)

func BenchmarkLargeEncryptedItem_GetValues(b *testing.B) {
	packer, unpacker, provider := testCreateEnv(b)

	item := &Item[Key]{
		Key:        Key{X: "A", Y: "B"},
		Attributes: make(map[string]any, 1000),
	}

	for i := range 100 {
		item.Attributes[fmt.Sprintf("%d", i)] = longStr
	}

	data, loader, err := packer(item)
	if err != nil {
		b.Fatalf("Unexpected error: %v", err)
	}

	ei, err := unpacker(data, loader)
	if err != nil {
		b.Fatalf("Unexpected error: %v", err)
	}

	ctx := context.TODO()

	for i := 0; i < b.N; i++ {
		_, err := ei.GetValues(ctx, []string{"1"}, provider)
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

func createKeyEnv(t testHandler) (func(*Key) ([]byte, DataLoader[Key], error), func(data []byte, dataLoader DataLoader[Key]) (*Key, error)) {

	getProvider := func() EnvelopeKeyProvider {
		ki := &EnvelopeKeyProviderInfo{
			ID:  "Key2",
			Key: []byte("91234567890123456789012345678912"),
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

	testPack := func(key *Key) ([]byte, DataLoader[Key], error) {

		pParams := &PackParams[Key]{
			Provider: provider,
			Creator:  NewKeyCreator(defaultLen),
			Packer:   serialiser,
			Approach: serialise.NewMinDataApproachWithVersion(serialise.V1),
		}

		info, err := PackKey(key, pParams)
		if err != nil {
			return nil, nil, err
		}

		dataLoader := func(ctx context.Context, keys []Key) (map[string][]byte, error) {
			return nil, nil
		}

		return info, dataLoader, nil
	}

	testUnpack := func(data []byte, dataLoader DataLoader[Key]) (*Key, error) {

		uParams := &UnpackParams[Key]{
			IDRetriever: idRetriever,
			Provider:    provider,
			DataLoader:  dataLoader,
		}

		key, err := UnpackKey(context.TODO(), data, uParams)
		if err != nil {
			return nil, err
		}

		return key, nil
	}

	return testPack, testUnpack
}

func TestPackKey(t *testing.T) {

	p, u := createKeyEnv(t)

	tests := []Key{
		{
			X: "ABC",
			Y: "XYZ",
		},
		{
			X: "ABC",
			Y: "",
		},
		{
			X: "",
			Y: "",
		},
		{
			X: "",
			Y: "XYZ",
		},
	}

	for _, test := range tests {

		b, d, err := p(&test)
		if err != nil {
			t.Fatalf("Unexpected error during PackKey: %v", err)
		}

		key2, err := u(b, d)
		if err != nil {
			t.Fatalf("Unexpected error during UnpackKey: %v", err)
		}

		if key2 == nil {
			t.Fatalf("Unpacked key is nil when should be an instance")
		}

		if test != *key2 {
			t.Fatalf("Unexpected mismatch in keys: expected: %v, got: %v", test, *key2)
		}
	}
}

func TestPackKey_1(t *testing.T) {

	p, _ := createKeyEnv(t)

	b, d, err := p(nil)
	if err == nil {
		t.Fatal("Unexpected success during PackKey: expected error")
	}
	if !errors.Is(err, ErrKeyMustNotBeNil) {
		t.Fatalf("Unexpected error returned: expected: %v, got: %v", err, ErrKeyMustNotBeNil)
	}

	if b != nil {
		t.Fatal("Unexpected []byte returned from PackKey")
	}
	if d != nil {
		t.Fatal("Unexpected DataLoader returned from PackKey")
	}
}
