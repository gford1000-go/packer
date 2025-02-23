package packer

import (
	"context"
	"crypto/aes"
	"crypto/rand"
	"errors"

	"github.com/gford1000-go/serialise"
)

// EnvelopeKeyProvider creates unique encryption keys that can be used for AES-GCM encryption
// This is used by Pack and Unpack to secure all the information provided to them.
type EnvelopeKeyProvider interface {
	// ID returns the identifier of the provider instance
	ID() EnvelopeKeyID
	// New returns a unique key as to parts: pre-encrypted byte slice, and the key itself
	New() ([]byte, []byte, error)
	// Decrypted returns the key from the pre-encrypted byte slice returned by New()
	Decrypt(ctx context.Context, encryptedKey []byte) ([]byte, error)
}

// EnvelopeKeyID type distinguishes envelope key identifiers from other strings
type EnvelopeKeyID string

// EnvelopeKeyProviderInfo associates an identifier to an envelope key
type EnvelopeKeyProviderInfo struct {
	ID  EnvelopeKeyID
	Key []byte
}

// ErrProviderMustHaveAnID raised if the EnveloperKeyProviderInfo has no ID
var ErrProviderMustHaveAnID = errors.New("envelope key provider must have a valid ID")

// ErrProviderMustHaveKey raise if teh EnveloperKeyProviderInfo has an invalid key
var ErrProviderMustHaveKey = errors.New("envelope key provider must have a valid AES-GCM key")

func (e *EnvelopeKeyProviderInfo) validate() error {
	if len(e.ID) == 0 {
		return ErrProviderMustHaveAnID
	}
	if len(e.Key) != 2*aes.BlockSize {
		return ErrProviderMustHaveKey
	}

	return nil
}

// EnveloperKeyProviderFinder allows EnvelopeKeyProviders to be found from their EnvelopeKeyID
type EnveloperKeyProviderFinder func(EnvelopeKeyID) (EnvelopeKeyProvider, error)

// ErrMissingEnvelopeKeyProviderInfo if no key information is provided to NewEnvelopeKeyProvider
var ErrMissingEnvelopeKeyProviderInfo = errors.New("keyInfo must not be nil")

// ErrMissingFinder if an EnveloperKeyProviderFinder is not provided to NewEnvelopeKeyProvider
var ErrMissingFinder = errors.New("finder must not be nil")

// NewEnvelopeKeyProvider creates a new instance of an EnvelopeKeyProvider, for both encryption and decryption,
// using the keyInfo provided.
func NewEnvelopeKeyProvider(keyInfo *EnvelopeKeyProviderInfo, finder EnveloperKeyProviderFinder) (EnvelopeKeyProvider, error) {

	if keyInfo == nil {
		return nil, ErrMissingEnvelopeKeyProviderInfo
	}
	if err := keyInfo.validate(); err != nil {
		return nil, err
	}
	if finder == nil {
		return nil, ErrMissingFinder
	}

	o := serialise.Options{}
	serialise.WithAESGCMEncryption(keyInfo.Key)(&o)

	return &evKeyProvider{
		dec:    o.Decryptor,
		enc:    o.Encryptor,
		finder: finder,
		id:     keyInfo.ID,
	}, nil
}

type evKeyProvider struct {
	dec    func([]byte) ([]byte, error)
	enc    func([]byte) ([]byte, error)
	finder EnveloperKeyProviderFinder
	id     EnvelopeKeyID
}

func (e *evKeyProvider) ID() EnvelopeKeyID {
	return e.id
}

func (e *evKeyProvider) New() ([]byte, []byte, error) {

	newKey := make([]byte, 2*aes.BlockSize)
	_, err := rand.Reader.Read(newKey)
	if err != nil {
		return nil, nil, err
	}

	encryptedKey, err := e.enc(newKey)
	if err != nil {
		return nil, nil, err
	}

	b, _, err := serialise.ToBytesMany(
		[]any{
			string(e.id),
			encryptedKey,
		}, serialise.WithSerialisationApproach(serialise.NewMinDataApproachWithVersion(serialise.V1)))
	if err != nil {
		return nil, nil, err
	}

	return b, newKey, nil
}

// ErrKeyProviderDecryptError raised if the provided encryptedKey data cannot be decrypted correctly
var ErrKeyProviderDecryptError = errors.New("invalid encrypted key provided - failed to decrypt")

func (e *evKeyProvider) Decrypt(ctx context.Context, encryptedKey []byte) ([]byte, error) {

	v, err := serialise.FromBytesMany(encryptedKey, serialise.NewMinDataApproachWithVersion(serialise.V1))
	if err != nil {
		return nil, err
	}

	if len(v) != 2 {
		return nil, ErrKeyDeserialisationError
	}

	id, ok := v[0].(string)
	if !ok {
		return nil, ErrKeyDeserialisationError
	}

	if EnvelopeKeyID(id) != e.id {
		other, err := e.finder(EnvelopeKeyID(id))
		if err != nil {
			return nil, err
		}
		return other.Decrypt(ctx, encryptedKey)
	}

	key, ok := v[1].([]byte)
	if !ok {
		return nil, ErrKeyDeserialisationError
	}

	return e.dec(key)
}
