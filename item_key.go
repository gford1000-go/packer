package packer

import (
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
	Decrypt(encryptedKey []byte) ([]byte, error)
}

// serialiseI64 ensures a standard treatment of int64 serialisation
func serialiseI64(v int64) ([]byte, error) {
	b, _, err := serialise.ToBytes(v, serialise.WithSerialisationApproach(serialise.NewMinDataApproachWithVersion(serialise.V1)))
	if err != nil {
		return nil, err
	}
	return b, nil
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

	b := []byte(keyInfo.ID)
	bs, err := serialiseI64(int64(len(b)))
	if err != nil {
		return nil, err
	}

	return &evKeyProvider{
		dec:    o.Decryptor,
		enc:    o.Encryptor,
		finder: finder,
		id:     keyInfo.ID,
		l:      int64(len(bs)),
		prefix: append(bs, b...),
	}, nil
}

type evKeyProvider struct {
	dec    func([]byte) ([]byte, error)
	enc    func([]byte) ([]byte, error)
	finder EnveloperKeyProviderFinder
	id     EnvelopeKeyID
	l      int64
	prefix []byte
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

	return append(e.prefix, encryptedKey...), newKey, nil
}

func deserialiseI64(data []byte) (int64, error) {
	v, err := serialise.FromBytes(data, serialise.NewMinDataApproachWithVersion(serialise.V1))
	if err != nil {
		return 0, err
	}
	if i, ok := v.(int64); ok {
		return i, nil
	}
	panic("Should never have an issue deserialising int64")
}

var ErrKeyProviderDecryptError = errors.New("invalid encrypted key provided - failed to decrypt")

func (e *evKeyProvider) Decrypt(encryptedKey []byte) ([]byte, error) {

	if int64(len(encryptedKey)) < e.l {
		return nil, ErrKeyProviderDecryptError
	}

	idSize, err := deserialiseI64(encryptedKey[0:e.l])
	if err != nil {
		return nil, err
	}

	if int64(len(encryptedKey)) < idSize+e.l {
		return nil, ErrKeyProviderDecryptError
	}
	id := EnvelopeKeyID(encryptedKey[e.l : e.l+idSize])

	// Could be that we have a valid encryptedKey, but using another envelope key.
	// This should not generate an error if we can locate the other key.
	if id != e.id {
		other, err := e.finder(id)
		if err != nil {
			return nil, err
		}
		return other.Decrypt(encryptedKey)
	}

	return e.dec(encryptedKey[e.l+idSize:])
}
