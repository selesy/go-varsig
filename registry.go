package varsig

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type Version uint64

const (
	Version0 Version = 0
	Version1 Version = 1
)

// DecodeFunc is a function that parses the varsig representing a specific
// signing algorithm.
type DecodeFunc func(*bytes.Reader, Version, SignAlgorithm) (Varsig, error)

// Registry contains a mapping between known signing algorithms, and
// functions that can parse varsigs for that signing algorithm.
type Registry map[SignAlgorithm]DecodeFunc

// DefaultRegistry provides a Registry containing the mappings for the
// signing algorithms which have an implementation within this library.
func DefaultRegistry() Registry {
	return map[SignAlgorithm]DecodeFunc{
		SignAlgorithmRSA:            decodeRSA,
		SignAlgorithmEdDSA:          decodeEd25519,
		SignAlgorithmEd448:          decodeEd25519,
		SignAlgorithmECDSAP256:      notYetImplementedVarsigDecoder,
		SignAlgorithmECDSASecp256k1: notYetImplementedVarsigDecoder,
		SignAlgorithmECDSAP521:      notYetImplementedVarsigDecoder,
	}
}

// NewRegistry creates an empty Registry.
func NewRegistry() Registry {
	return make(Registry)
}

// Register allows new mappings between a signing algorithm and its parsing
// function to the Registry.
func (rs Registry) Register(alg SignAlgorithm, decodeFunc DecodeFunc) {
	rs[alg] = decodeFunc
}

// Decode converts the provided data into one of the registered Varsig
// types.
func (rs Registry) Decode(data []byte) (Varsig, error) {
	return rs.DecodeStream(bytes.NewReader(data))
}

// DecodeStream converts data read from the provided io.Reader into one
// of the registered Varsig types.
func (rs Registry) DecodeStream(r *bytes.Reader) (Varsig, error) {
	pre, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadPrefix, err)
	}

	if pre != Prefix {
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrBadPrefix, Prefix, pre)
	}

	vers, signAlg, err := rs.decodeVersAndSignAlg(r)
	if err != nil {
		return nil, err
	}

	decodeFunc, ok := rs[SignAlgorithm(signAlg)]
	if !ok {
		return nil, fmt.Errorf("%w: %x", ErrUnknownSignAlgorithm, signAlg)
	}

	return decodeFunc(r, vers, signAlg)
}

func (rs Registry) decodeVersAndSignAlg(r *bytes.Reader) (Version, SignAlgorithm, error) {
	vers, err := binary.ReadUvarint(r)
	if err != nil {
		return Version(vers), 0, err
	}

	if vers > 1 && vers < 64 {
		return Version(vers), 0, fmt.Errorf("%w: %d", ErrUnsupportedVersion, vers)
	}

	if vers >= 64 {
		return 0, SignAlgorithm(vers), nil
	}

	signAlg, err := binary.ReadUvarint(r)

	return Version(vers), SignAlgorithm(signAlg), err
}

func notYetImplementedVarsigDecoder(_ *bytes.Reader, vers Version, signAlg SignAlgorithm) (Varsig, error) {
	return nil, fmt.Errorf("%w: Version: %d, SignAlgorithm: %x", ErrNotYetImplemented, vers, signAlg)
}
