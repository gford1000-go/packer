package packer

import (
	"fmt"

	"github.com/gford1000-go/serialise"
)

// serialiseI64 ensures a standard treatment of int64 serialisation
func serialiseI64(v int64) ([]byte, error) {
	b, _, err := serialise.ToBytes(v, serialise.WithSerialisationApproach(serialise.NewMinDataApproachWithVersion(serialise.V1)))
	if err != nil {
		return nil, err
	}
	return b, nil
}

// sizeOfSerialisedI64 returns standard length of int64 when serialised
func sizeOfSerialisedI64() int {
	b, err := serialiseI64(0)
	if err != nil {
		panic(fmt.Sprintf("unexpected error when determining serialised size of int64: %v", err))
	}
	return len(b)
}

// deserialiseI64 deserialises an int64 from material created by serialiseI64
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
