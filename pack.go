package packer

import (
	"errors"

	"github.com/gford1000-go/serialise"
)

type Options struct {
	// Which packing mechanism is used
	packingVersion PackVersion
	// Serialisation options
	serialiseOptions []func(*serialise.Options)
	// Max size of an individual attribute - must be less than maxSize
	maxAttrValueSize uint64
	// Max size in bytes
	maxSize uint64
	// Seed used for testing
	seed int64
	// Size of the random attribute names
	attrNameSize uint8
	// Number of retries allowed to create unique attribute name
	attrNameRetries uint8
}

// WithSerialisationOptions allows options for serialisation to be applied
func WithSerialisationOptions(o *Options, opts ...func(*serialise.Options)) func(o *Options) {
	return func(o *Options) {
		o.serialiseOptions = opts
	}
}

// WithMaximumKBSize allows the setting of the maximum size for each returned item.
// If not set, then any length is allowed (i.e. only one item is returned).
func WithMaximumKBSize(o *Options, sizeInKB uint16) func(o *Options) {
	return func(o *Options) {
		o.maxSize = uint64(sizeInKB * 1024)
	}
}

// WithAttributeValueMaximumKBSize allows the setting of the maximum size for the
// length of data held in an attribute after Packing.
// Must be less than the maxSize of the entire item
func WithAttributeValueMaximumKBSize(o *Options, sizeInKB uint16) func(o *Options) {
	return func(o *Options) {
		o.maxAttrValueSize = uint64(sizeInKB * 1024)
	}
}

// withSeed is only used for testing, to generate a consistent set of attribute names
func withSeed(o *Options, seed int64) func(o *Options) {
	return func(o *Options) {
		o.seed = seed
	}
}

// WithAttributeNameSize sets the size of the attribute name
func WithAttributeNameSize(o *Options, size uint8) func(o *Options) {
	if size < 2 {
		panic("AttributeNameSize must be at least two")
	}
	return func(o *Options) {
		o.attrNameSize = size
	}
}

// WithAttributeNameRetries sets the number of retries to create a unique attribute name
func WithAttributeNameRetries(o *Options, retries uint8) func(o *Options) {
	return func(o *Options) {
		o.attrNameRetries = retries
	}
}

func WithPackingVersion(o *Options, version PackVersion) func(o *Options) {
	if version < UnknownVersion || version >= OutOfRange {
		panic("invalid PackVerion value provided")
	}
	return func(o *Options) {
		o.packingVersion = version
	}
}

// PackVersion describes a version of a Pack serialisation implementation
// All breaking changes to serialisation will trigger an increment, to ensure
// backwards compatibility to any consumers with data serialised using existing versions.
type PackVersion int8

const (
	UnknownVersion PackVersion = iota
	V1
	OutOfRange
)

// PackParams provide details on which mechanism should be used to serialise data
type PackParams[T comparable] struct {
	// Provider vends the encryption key for encryption and decryption
	Provider EnvelopeKeyProvider
	// Creator ensures that new instances of T can be created when required
	Creator IDCreator[T]
	// Packer ensures that instances of T can be serialised correctly
	Packer IDSerialiser[T]
	// Approach defines which serialisation approach is used for the attribute data
	Approach serialise.Approach
}

// ErrParamsNoProvider raised if no Provider is included in PackParms
var ErrParamsNoProvider = errors.New("params must include a Provider to vend the data encryption key")

// ErrParamsNoIDCreator raised if a Creator is not included in PackParams
var ErrParamsNoIDCreator = errors.New("params must include a Creator to allow new keys to be created when required")

// ErrParamsNoIDSerialiser raised if a a Packer is not included in PackParams
var ErrParamsNoIDSerialiser = errors.New("params must include a Packer to allow keys to be serialised correctly when required")

// ErrParamsNoApproach raised if there is no Approach for serialisation of the data provided in PackParams
var ErrParamsNoApproach = errors.New("params must include the serialise.Approach to use for serialising attribute data")

func (p *PackParams[T]) validate() error {
	if p.Provider == nil {
		return ErrParamsNoProvider
	}
	if p.Creator == nil {
		return ErrParamsNoIDCreator
	}
	if p.Packer == nil {
		return ErrParamsNoIDSerialiser
	}
	if p.Approach == nil {
		return ErrParamsNoApproach
	}
	return nil
}

// ErrPackNoAttributes raised when Pack called with an empty map of attribute values
var ErrPackNoAttributes = errors.New("no attributes to serialsie in call to Pack")

// ErrPackNoParams raised when Pack is called without any PackParams specified
var ErrPackNoParams = errors.New("no PackParams provided")

// ErrUnsupportedPackVersion raised if a packing version is requested that is not available
var ErrUnsupportedPackVersion = errors.New("unsupported pack version requested")

const (
	defaultAttributeNameSize    uint8       = 3
	defaultAttributeNameRetries uint8       = 1
	defaultMaxSize              uint64      = 350 * 1024
	defaultAttributeMaxSize     uint64      = 100 * 1024
	defaultPackingVersion       PackVersion = V1
)

// Pack
func Pack[T comparable](key T, attrs map[string]any, params *PackParams[T], opts ...func(*Options)) ([]byte, map[T]map[string][]byte, error) {

	if len(attrs) == 0 {
		return nil, nil, ErrPackNoAttributes
	}
	if params == nil {
		return nil, nil, ErrPackNoParams
	}
	if err := params.validate(); err != nil {
		return nil, nil, err
	}

	o := &Options{}
	for _, opt := range opts {
		opt(o)
	}
	if o.packingVersion == UnknownVersion {
		o.packingVersion = defaultPackingVersion
	}
	if o.attrNameSize < 2 {
		o.attrNameSize = defaultAttributeNameSize
	}
	if o.attrNameRetries == 0 {
		o.attrNameRetries = defaultAttributeNameRetries
	}
	if o.maxSize == 0 {
		o.maxSize = defaultMaxSize
	}
	if o.maxAttrValueSize == 0 {
		o.maxAttrValueSize = defaultAttributeMaxSize
	}
	if o.maxAttrValueSize > o.maxSize {
		o.maxAttrValueSize = o.maxSize
	}

	// Ensure the Approach specified in the params will be used
	if len(o.serialiseOptions) == 0 {
		o.serialiseOptions = []func(*serialise.Options){serialise.WithSerialisationApproach(params.Approach)}
	} else {
		o.serialiseOptions = append(o.serialiseOptions, serialise.WithSerialisationApproach(params.Approach))
	}

	// Retrieve the one-time key details for this packing call
	encryptedKey, encKey, err := params.Provider.New()
	if err != nil {
		return nil, nil, err
	}
	// Ensure all data is encrypted with this key during serialisation
	o.serialiseOptions = append(o.serialiseOptions, serialise.WithAESGCMEncryption(encKey))

	switch o.packingVersion {
	case V1:
		d := &itemPackingDetailsV1[T]{
			key:      key,
			attrs:    attrs,
			params:   params,
			opts:     o,
			elements: []T{},
			attrMap:  map[string][]string{},
			valMap:   map[string][]byte{},
		}
		return d.pack(encryptedKey, encKey)
	default:
		return nil, nil, ErrUnsupportedPackVersion
	}
}
