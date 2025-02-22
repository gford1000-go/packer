package packer

// IDCreator returns unique instances of T (i.e. when compared)
type IDCreator[T comparable] interface {
	// ID returns a unique instance of T
	ID() T
}

// IDSerialiser can serialise and deserialise an instance of T
type IDSerialiser[T comparable] interface {
	// Name identifies the serialiser
	Name() string
	// Pack converts an instance of T to a byte slice
	Pack(t T) ([]byte, error)
	// Unpack recovers an instance of T from a byte slice
	Unpack(data []byte) (T, error)
}
