package packer

import (
	"context"
	c "crypto/rand"
	"errors"
	"math/big"
	"sort"

	"github.com/gford1000-go/serialise"
)

type itemPackingDetailsV1[T comparable] struct {
	params *PackParams[T]
	opts   *Options
}

func (d *itemPackingDetailsV1[T]) pack(item *Item[T], encryptedKey, encKey []byte) ([]byte, map[T]map[string][]byte, error) {

	if d.opts == nil {
		d.opts = &Options{}
	}
	if d.opts.serialiseOptions == nil {
		d.opts.serialiseOptions = []func(*serialise.Options){serialise.WithSerialisationApproach(d.params.Approach)}
	} else {
		d.opts.serialiseOptions = append(d.opts.serialiseOptions, serialise.WithSerialisationApproach(d.params.Approach))
	}
	d.opts.serialiseOptions = append(d.opts.serialiseOptions, serialise.WithAESGCMEncryption(encKey))

	attrMap, valMap, err := d.createMaps(item.Attributes)
	if err != nil {
		return nil, nil, err
	}

	elements, output := d.createElements(item.Key, valMap)

	bKey, err := d.params.Packer.Pack(item.Key)
	if err != nil {
		return nil, nil, err
	}

	bAttrMap, err := d.packAttrMap(attrMap)
	if err != nil {
		return nil, nil, err
	}

	bElements, err := d.packElementsSlice(elements)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt these details, so they are only accessible if envelope key is available
	packData := []any{
		bKey,
		bAttrMap,
		bElements,
	}
	b, _, err := serialise.ToBytesMany(packData, d.opts.serialiseOptions...)
	if err != nil {
		return nil, nil, err
	}

	// Final envelope of information that allows unpacking; can be visible
	finalisedData := []any{
		encryptedKey,
		d.params.Packer.Name(),
		d.params.Approach.Name(),
		b,
	}

	// Always use V1 to guarantee we can bootstrap back to the finalised data
	b, _, err = serialise.ToBytesMany(finalisedData, serialise.WithSerialisationApproach(serialise.NewMinDataApproachWithVersion(serialise.V1)))
	if err != nil {
		return nil, nil, err
	}

	// Output is returned separately, as all attribute data values are encrypted and attribute names are randomised
	return b, output, nil
}

var ErrInvalidDataToUnpack = errors.New("the provided data cannot not be deserialised")

func (d *itemPackingDetailsV1[T]) unpack(ctx context.Context, data []byte, envKeyProvider EnvelopeKeyProvider, loader DataLoader[T], idRetriever GetIDSerialiser[T]) (*EncryptedItem[T], error) {

	// Always use V1 to guarantee we can bootstrap back to the finalised data
	finalisedData, err := serialise.FromBytesMany(data, serialise.NewMinDataApproachWithVersion(serialise.V1))
	if err != nil {
		return nil, err
	}

	if len(finalisedData) != 4 {
		return nil, ErrInvalidDataToUnpack
	}

	encryptedKey, ok := finalisedData[0].([]byte)
	if !ok {
		return nil, ErrInvalidDataToUnpack
	}

	packerName, ok := finalisedData[1].(string)
	if !ok {
		return nil, ErrInvalidDataToUnpack
	}
	packer, err := idRetriever(packerName)
	if err != nil {
		return nil, err
	}

	approachName, ok := finalisedData[2].(string)
	if !ok {
		return nil, ErrInvalidDataToUnpack
	}
	approach, err := serialise.GetApproach(approachName)
	if err != nil {
		return nil, err
	}

	b, ok := finalisedData[3].([]byte)
	if !ok {
		return nil, ErrInvalidDataToUnpack
	}

	encKey, err := envKeyProvider.Decrypt(ctx, encryptedKey)
	if err != nil {
		return nil, err
	}

	packData, err := serialise.FromBytesMany(b, approach, serialise.WithAESGCMEncryption(encKey))
	if err != nil {
		return nil, err
	}

	if len(packData) != 3 {
		return nil, ErrInvalidDataToUnpack
	}

	bKey, ok := packData[0].([]byte)
	if !ok {
		return nil, ErrInvalidDataToUnpack
	}

	key, err := packer.Unpack(bKey)
	if err != nil {
		return nil, err
	}

	bAttrMap, ok := packData[1].([]byte)
	if !ok {
		return nil, ErrInvalidDataToUnpack
	}

	attrMap, err := d.unpackAttrMap(bAttrMap, approach)
	if err != nil {
		return nil, err
	}

	bElements, ok := packData[2].([]byte)
	if !ok {
		return nil, ErrInvalidDataToUnpack
	}
	elements, err := d.unpackElementsSlice(bElements, approach, packer)
	if err != nil {
		return nil, err
	}

	md, err := loader(ctx, elements)
	if err != nil {
		return nil, err
	}

	dataMap := map[string][]byte{}

	for k, v := range attrMap {
		b := []byte{}
		for _, a := range v {
			if part, ok := md[a]; !ok {
				return nil, ErrInvalidDataToUnpack
			} else {
				b = append(b, part...)
			}
		}
		dataMap[k] = b
	}

	output := &EncryptedItem[T]{
		key:          key,
		approach:     approach,
		encryptedKey: encryptedKey,
		attributes:   dataMap,
		packer:       packer,
	}

	return output, nil
}

type byteSort struct {
	k string
	v []byte
}

type byteSortSet []byteSort

func (b byteSortSet) Len() int           { return len(b) }
func (b byteSortSet) Swap(i, j int)      { b[i], b[j] = b[j], b[i] }
func (b byteSortSet) Less(i, j int) bool { return len(b[i].v) < len(b[j].v) }

func (d *itemPackingDetailsV1[T]) createElements(key T, vals map[string][]byte) ([]T, map[T]map[string][]byte) {

	remaining := int64(d.opts.maxSize - minSize)
	rest := byteSortSet{}

	for k, v := range vals {
		remaining -= int64(len(k) + len(v))
		if remaining < 0 {
			rest = append(rest, byteSort{k: k, v: v})
		}
	}

	outputKeys := []T{key}
	outputAttSet := map[T]map[string][]byte{
		key: vals,
	}

	if len(rest) == 0 {
		// All attributes contained in a single element - nothing more to do
		return outputKeys, outputAttSet
	}

	// Bin pack the remainder
	sort.Sort(rest)

	type bin struct {
		size    uint64
		content []*byteSort
	}

	var bins []bin

	for _, bs := range rest {
		placed := false
		for i := range bins {
			if bins[i].size+uint64(len(bs.k)+len(bs.v)) < d.opts.maxSize {
				bins[i].content = append(bins[i].content, &bs)
				bins[i].size += uint64(len(bs.k) + len(bs.v))
				placed = true
				break
			}
		}
		if !placed {
			newBin := bin{
				size:    uint64(len(bs.k) + len(bs.v)),
				content: []*byteSort{&bs},
			}
			bins = append(bins, newBin)
		}
	}

	// Create elements and allocate bin to each
	for _, bin := range bins {
		t := d.params.Creator.ID()
		outputKeys = append(outputKeys, t)

		m := map[string][]byte{}
		outputAttSet[t] = m

		for _, c := range bin.content {
			m[c.k] = c.v
		}
	}

	return outputKeys, outputAttSet
}

func (d *itemPackingDetailsV1[T]) packAttrMap(attrMap map[string][]string) ([]byte, error) {

	items := make([]any, len(attrMap))

	i := 0
	for k, v := range attrMap {
		item := []string{k}
		item = append(item, v...)
		items[i] = item
		i++
	}

	b, _, err := serialise.ToBytesMany(items, serialise.WithSerialisationApproach(d.params.Approach))
	return b, err
}

var ErrInvalidDataToDeserialiseAttrMap = errors.New("invalid data, cannot deserialise attribute map")

func (d *itemPackingDetailsV1[T]) unpackAttrMap(data []byte, approach serialise.Approach) (map[string][]string, error) {

	v, err := serialise.FromBytesMany(data, approach)
	if err != nil {
		return nil, err
	}

	attrMap := make(map[string][]string, len(v))

	for i := 0; i < len(v); i++ {
		ss, ok := v[i].([]string)
		if !ok {
			return nil, ErrInvalidDataToDeserialiseAttrMap
		}
		if len(ss) < 2 {
			return nil, ErrInvalidDataToDeserialiseAttrMap
		}
		attrMap[ss[0]] = ss[1:]
	}

	return attrMap, nil
}

func (d *itemPackingDetailsV1[T]) packElementsSlice(elements []T) ([]byte, error) {

	eles := make([]any, len(elements))

	for i, ele := range elements {
		b, err := d.params.Packer.Pack(ele)
		if err != nil {
			return nil, err
		}
		eles[i] = b
	}

	b, _, err := serialise.ToBytesMany(eles, serialise.WithSerialisationApproach(d.params.Approach))
	return b, err
}

var ErrInvalidDataToDeserialiseElements = errors.New("invalid data, cannot deserialise element slice")

func (d *itemPackingDetailsV1[T]) unpackElementsSlice(data []byte, approach serialise.Approach, packer IDSerialiser[T]) ([]T, error) {

	v, err := serialise.FromBytesMany(data, approach)
	if err != nil {
		return nil, err
	}

	elements := make([]T, len(v))

	for i := 0; i < len(v); i++ {
		b, ok := v[i].([]byte)
		if !ok {
			return nil, ErrInvalidDataToDeserialiseElements
		}

		t, err := packer.Unpack(b)
		if err != nil {
			return nil, err
		}

		elements[i] = t
	}

	return elements, nil
}

func (d *itemPackingDetailsV1[T]) createMaps(attrs map[string]any) (map[string][]string, map[string][]byte, error) {
	used := map[string]bool{}
	attrMap := map[string][]string{}
	valMap := map[string][]byte{}

	for k, v := range attrs {
		var b []byte
		var err error
		// Individual attribute values are serialised using the user options - which will include encryption
		switch vv := v.(type) {
		case T:
			b, err = d.params.Packer.Pack(vv)
			if err != nil {
				return nil, nil, err
			}
			b, _, err = serialise.ToBytesMany([]any{true, b}, d.opts.serialiseOptions...)
		case *T:
			b, err = d.params.Packer.Pack(*vv)
			if err != nil {
				return nil, nil, err
			}
			b, _, err = serialise.ToBytesMany([]any{false, b}, d.opts.serialiseOptions...)
		case []T:
			tt := make([]any, len(vv)+2)
			tt[0] = true
			tt[1] = int64(len(vv))
			for i := 0; i < len(vv); i++ {
				tt[i+2], err = d.params.Packer.Pack(vv[i])
				if err != nil {
					return nil, nil, err
				}
			}
			b, _, err = serialise.ToBytesMany(tt, d.opts.serialiseOptions...)
		case []*T:
			tt := make([]any, len(vv)+2)
			tt[0] = false
			tt[1] = int64(len(vv))
			for i := 0; i <= len(vv); i++ {
				tt[i+2], err = d.params.Packer.Pack(*vv[i])
				if err != nil {
					return nil, nil, err
				}
			}
			b, _, err = serialise.ToBytesMany(tt, d.opts.serialiseOptions...)
		default:
			b, _, err = serialise.ToBytesMany([]any{v}, d.opts.serialiseOptions...)
		}
		if err != nil {
			return nil, nil, err
		}

		// Where the serialised value exceedes the max size allowed, then
		// split it into chunks, each with its own unique attribute name.
		// attrMap then holds the array of attribute names in the correct
		// order to reconstruct the overall byte size when needed.
		attrMap[k] = []string{}
		for len(b) > int(d.opts.maxAttrValueSize) {
			an, err := d.uniqueAttributeName(used)
			if err != nil {
				return nil, nil, err
			}
			valMap[an] = b[0:d.opts.maxAttrValueSize]
			attrMap[k] = append(attrMap[k], an)
			b = b[d.opts.maxSize:]
		}
		an, err := d.uniqueAttributeName(used)
		if err != nil {
			return nil, nil, err
		}
		valMap[an] = b
		attrMap[k] = append(attrMap[k], an)
	}

	return attrMap, valMap, nil
}

// ErrUnableToCreateUniqueName raised if a unique attribute name cannot be determined before running out of retries
var ErrUnableToCreateUniqueName = errors.New("retries exceeded when creating random attribute names - increase the size of attribute names option")

func (d *itemPackingDetailsV1[T]) uniqueAttributeName(existing map[string]bool) (string, error) {

	cryptoRandOffset := func(n int) func() int {
		return func() int {
			i, err := c.Int(c.Reader, big.NewInt(int64(n)))
			if err != nil {
				panic(err)
			}
			return int(i.Int64())
		}
	}

	// Use a reduced selection so that attribute names are readable
	eles := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	randGen := cryptoRandOffset(len(eles))

	// Ensure don't loop forever if set of attribute names is exhaused.  Shouldn't happen though.
	for i := 0; i < int(d.opts.attrNameRetries); i++ {
		var b = make([]byte, d.opts.attrNameSize)
		for j := 0; j < int(d.opts.attrNameSize); j++ {
			b[j] = eles[randGen()]
		}

		s := string(b)
		if _, ok := existing[s]; !ok {
			existing[s] = true
			return s, nil
		}
	}

	return "", ErrUnableToCreateUniqueName
}
