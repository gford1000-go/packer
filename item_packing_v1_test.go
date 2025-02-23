package packer

import (
	"testing"

	"github.com/gford1000-go/serialise"
)

func TestItemPackingDetailsV1_PackElementsSlice(t *testing.T) {

	serialiser, err := NewKeySerialiser()
	if err != nil {
		t.Fatalf("Unexpected error creating KeySerialiser: %v", err)
	}

	tests := [][]Key{
		{},
		{
			{
				X: "A",
				Y: "B",
			},
		},
		{
			{
				X: "A",
				Y: "B",
			},
			{
				X: "ABC",
				Y: "BDE",
			},
		},
		{
			{
				X: "A",
				Y: "B",
			},
			{
				X: "ABC",
				Y: "BDE",
			},
			{
				X: "ABCDERFHDGEWUGWIEDGHWEUDF",
				Y: "BDEWEDW	Hhyewoddweduh3",
			},
		},
	}

	for _, elements := range tests {

		i := &itemPackingDetailsV1[Key]{
			params: &PackParams[Key]{
				Packer:   serialiser,
				Approach: serialise.NewMinDataApproachWithVersion(serialise.V1),
			},
			opts:     &Options{},
			elements: elements,
		}

		b, err := i.packElementsSlice()
		if err != nil {
			t.Fatalf("Unexpected error packing elements slice: %v", err)
		}

		err = i.unpackElementsSlice(b)
		if err != nil {
			t.Fatalf("Unexpected error unpacking elements slice: %v", err)
		}

		if len(elements) != len(i.elements) {
			t.Fatalf("Mismatch in length between original and deserialised elements")
		}

		for j := 0; j < len(elements); j++ {
			if elements[j] != i.elements[j] {
				t.Fatalf("Mismatch in values at element %d: wanted %v, got: %v", j, elements[j], i.elements[j])
			}
		}
	}
}
