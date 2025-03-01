package packer

import (
	"context"
	"errors"
	"fmt"
	"maps"

	"github.com/gford1000-go/serialise"
)

func Example() {
	// ---------------------------
	// 0. Create environment
	// ---------------------------

	// getProvider creates a simple envelope key management implementation
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
			panic(fmt.Sprintf("Unexpected error preparing provider: %v", err))
		}
		m[provider.ID()] = provider

		return provider
	}

	provider := getProvider()

	// NewKeySerialiser allows instances of Key to be serialised and recovered
	serialiser, err := NewKeySerialiser()
	if err != nil {
		panic(fmt.Sprintf("Unexpected error preparing Key serialiser: %v", err))
	}

	idRetriever := func(name string) (IDSerialiser[Key], error) {
		return serialiser, nil
	}

	// This creates an in-memory equivalent of a remote store, where data is durably stored by Key
	createDataStore := func() (func(info []byte, data map[Key]map[string][]byte), func(key Key) []byte, func(ctx context.Context, keys []Key) (map[string][]byte, error)) {
		type keyData struct {
			packInfo []byte
			attrs    map[string][]byte
		}

		store := map[Key]*keyData{}

		return func(info []byte, data map[Key]map[string][]byte) {
				for k, v := range data {
					if _, ok := store[k]; !ok {
						store[k] = &keyData{
							packInfo: info,
							attrs:    map[string][]byte{},
						}
					}
					for kk, vv := range v {
						store[k].attrs[kk] = vv
					}
				}
			},
			func(key Key) []byte {
				return store[key].packInfo
			},
			func(ctx context.Context, keys []Key) (map[string][]byte, error) {
				attrs := map[string][]byte{}

				for _, key := range keys {
					if m, ok := store[key]; ok {
						maps.Copy(attrs, m.attrs)
					}
				}

				return attrs, nil
			}
	}
	// Create interaction with the in-memory store
	addData, infoLoader, dataLoader := createDataStore()

	// ---------------------------
	// 1. Pack and store an item
	// ---------------------------

	// An item to be securely packed for storage
	item := &Item[Key]{
		Key: Key{X: "A", Y: "B"},
		Attributes: map[string]any{
			"xyz": string("Hello World"),
		},
	}

	// Parameters for packing data
	pParams := &PackParams[Key]{
		Provider: provider,
		Creator:  NewKeyCreator(),
		Packer:   serialiser,
		Approach: serialise.NewMinDataApproachWithVersion(serialise.V1),
	}

	// Packed ... get back encrypted attributes for the Item, plus additional packing information that should also be stored
	// durably with the attributes
	itemInfo, encryptedItemAttributes, _ := Pack[Key](item, pParams)

	// Store our serialised data to the store
	addData(itemInfo, encryptedItemAttributes)

	// ---------------------------
	// 2. Retrieve and unpack item
	// ---------------------------

	// Parameters for unpacking
	uParams := &UnpackParams[Key]{
		IDRetriever: idRetriever,
		Provider:    provider,
		DataLoader:  dataLoader,
	}

	// Get the itemInfo for the Key from the store
	retrievedItemInfo := infoLoader(item.Key)

	// Unpack the item based on its itemInfo
	// Returns an EncryptedKey, which continues to have its attribute values encrypted
	eItem, _ := Unpack(context.TODO(), retrievedItemInfo, uParams)

	// ---------------------------
	// 3. Confirm unpacked ok
	// ---------------------------

	// Retrieve decrypted values
	attrValues, _ := eItem.GetValues(context.TODO(), []string{"xyz"}, provider)

	fmt.Println(eItem.GetKey() == item.Key, item.Attributes["xyz"].(string) == attrValues["xyz"].(string))
	// Output: true true
}
