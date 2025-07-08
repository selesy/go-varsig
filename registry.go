package varsig

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Version represents which version of the varsig specification was used
// to produce Varsig value.
type Version uint64

// Constants for the existing varsig specifications
const (
	Version0 Version = 0
	Version1 Version = 1
)

// DecodeFunc is a function that parses the varsig representing a specific
// signing algorithm.
type DecodeFunc func(BytesReader, Version, Discriminator) (Varsig, error)

// Registry contains a mapping between known signing algorithms and
// functions that can parse varsigs for that signing algorithm.
type Registry map[Discriminator]DecodeFunc

// DefaultRegistry provides a Registry containing the mappings for the
// signing algorithms which have an implementation within this library.
func DefaultRegistry() Registry {
	return map[Discriminator]DecodeFunc{
		DiscriminatorRSA:            decodeRSA,
		DiscriminatorEdDSA:          decodeEd25519,
		DiscriminatorEd448:          decodeEd25519,
		DiscriminatorECDSAP256:      notYetImplementedVarsigDecoder,
		DiscriminatorECDSASecp256k1: notYetImplementedVarsigDecoder,
		DiscriminatorECDSAP521:      notYetImplementedVarsigDecoder,
	}
}

// NewRegistry creates an empty Registry.
func NewRegistry() Registry {
	return make(Registry)
}

// Register allows new mappings between a signing algorithm and its parsing
// function to the Registry.
func (rs Registry) Register(alg Discriminator, decodeFunc DecodeFunc) {
	rs[alg] = decodeFunc
}

// Decode converts the provided data into one of the registered Varsig
// types.
func (rs Registry) Decode(data []byte) (Varsig, error) {
	return rs.DecodeStream(bytes.NewReader(data))
}

// DecodeStream converts data read from the provided io.Reader into one
// of the registered Varsig types.
func (rs Registry) DecodeStream(r BytesReader) (Varsig, error) {
	pre, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadPrefix, err)
	}

	if pre != Prefix {
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrBadPrefix, Prefix, pre)
	}

	vers, disc, err := rs.decodeVersAnddisc(r)
	if err != nil {
		return nil, err
	}

	decodeFunc, ok := rs[Discriminator(disc)]
	if !ok {
		return nil, fmt.Errorf("%w: %x", ErrUnknownDiscriminator, disc)
	}

	return decodeFunc(r, vers, disc)
}

func (rs Registry) decodeVersAnddisc(r BytesReader) (Version, Discriminator, error) {
	vers, err := binary.ReadUvarint(r)
	if err != nil {
		return Version(vers), 0, err
	}

	if vers > 1 && vers < 64 {
		return Version(vers), 0, fmt.Errorf("%w: %d", ErrUnsupportedVersion, vers)
	}

	if vers >= 64 {
		return 0, Discriminator(vers), nil
	}

	disc, err := binary.ReadUvarint(r)

	return Version(vers), Discriminator(disc), err
}

func notYetImplementedVarsigDecoder(_ BytesReader, vers Version, disc Discriminator) (Varsig, error) {
	return nil, fmt.Errorf("%w: Version: %d, Discriminator: %x", ErrNotYetImplemented, vers, disc)
}
