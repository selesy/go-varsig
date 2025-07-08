// Package varsig implements v0.1.0 of the [Varsig specification].
//
// # Algorithm naming
//
// While there is no strict need for compatibility with JWA/JWT/JWE/JWS,
// all attempts are made to keep the algorithm names here consistent with
// the table provided in [section 3.1] of RFC7518 titled "JSON Web Algorithms.
// In cases where there is no equivalent name for an algorithm, a best-
// effort attempt at creating a name in the spirit of that specification is
// made.
//
// It should also be noted that algorithm in this context might in fact be
// a pseudonym - for cryptographical signing algorithms that require the
// signed data to be hashed first, these names commonly refer to the
// combination of that signing algorithm and the hash algorithm.
//
// [section 3.1]: https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
//
// [Varsig Specification]: https://github.com/ChainAgnostic/varsig
package varsig

import (
	"bytes"
	"encoding/binary"
	"io"
)

// Varsig represents types that describe how a signature was generated
// and thus how to interpret the signature and verify the signed data.
type Varsig interface {
	// accessors for fields that are common to all varsig
	Version() Version
	Discriminator() Discriminator
	PayloadEncoding() PayloadEncoding
	Signature() []byte

	// Operations that are common to all varsig
	Encode() []byte
}

// Decode converts the provided data into one of the Varsig types
// provided by the DefaultRegistry.
func Decode(data []byte) (Varsig, error) {
	return DefaultRegistry().Decode(data)
}

// DecodeStream converts data read from the provided io.Reader into one
// of the Varsig types provided by the DefaultRegistry.
func DecodeStream(r *bytes.Reader) (Varsig, error) {
	return DefaultRegistry().DecodeStream(r)
}

type varsig[T Varsig] struct {
	vers   Version
	disc   Discriminator
	payEnc PayloadEncoding
	sig    []byte
}

// Version returns the varsig's version field.
func (v varsig[_]) Version() Version {
	return v.vers
}

// Discriminator returns the algorithm used to produce corresponding
// signature.
func (v varsig[_]) Discriminator() Discriminator {
	return v.disc
}

// PayloadEncoding returns the codec that was used to encode the signed
// data.
func (v varsig[_]) PayloadEncoding() PayloadEncoding {
	return v.payEnc
}

// Signature returns the cryptographic signature of the signed data. This
// value is never present in a varsig >= v1 and must either be a valid
// signature with the correct length or empty in varsig < v1.
func (v varsig[_]) Signature() []byte {
	return v.sig
}

func (v *varsig[_]) encode() []byte {
	var buf []byte

	buf = binary.AppendUvarint(buf, Prefix)

	if v.Version() == Version1 {
		buf = binary.AppendUvarint(buf, uint64(Version1))
	}

	buf = binary.AppendUvarint(buf, uint64(v.disc))

	return buf
}

func (v *varsig[T]) decodePayEncAndSig(r *bytes.Reader, varsig *T, expectedLength uint64) (*T, error) {
	payEnc, err := DecodePayloadEncoding(r, v.Version())
	if err != nil {
		return nil, err
	}

	v.payEnc = payEnc

	signature, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	v.sig = signature

	return v.validateSig(varsig, expectedLength)
}

func (v *varsig[T]) validateSig(varsig *T, expectedLength uint64) (*T, error) {
	if v.Version() == Version0 && len(v.sig) == 0 {
		return varsig, ErrMissingSignature
	}

	if v.Version() == Version0 && uint64(len(v.sig)) != expectedLength {
		return nil, ErrUnexpectedSignatureSize
	}

	if v.Version() == Version1 && len(v.sig) != 0 {
		return nil, ErrUnexpectedSignaturePresent
	}

	return varsig, nil

}
