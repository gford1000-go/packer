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
			opts: &Options{},
		}

		b, err := i.packElementsSlice(elements)
		if err != nil {
			t.Fatalf("Unexpected error packing elements slice: %v", err)
		}

		elements2, err := i.unpackElementsSlice(b, i.params.Approach, i.params.Packer)
		if err != nil {
			t.Fatalf("Unexpected error unpacking elements slice: %v", err)
		}

		if len(elements) != len(elements2) {
			t.Fatalf("Mismatch in length between original and deserialised elements")
		}

		for j := 0; j < len(elements); j++ {
			if elements[j] != elements2[j] {
				t.Fatalf("Mismatch in values at element %d: wanted %v, got: %v", j, elements[j], elements2[j])
			}
		}
	}
}
