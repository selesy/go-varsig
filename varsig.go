// Package varsig implements v1.0.0 of the [Varsig specification] with
// limited support for varsig < v1.  This is primarily in support of the
// UCAN v1.0.0 specification and will be deprecated in the future.
//
// # Common algorithm naming
//
// While there is no strict need for compatibility with JWA/JWT/JWE/JWS,
// all attempts are made to keep the algorithm names here consistent with
// list made available at the [IANA Registry] titled "JSON Web Signature
// and Encryption Algorithms" (JOSE.)
//
// It should also be noted that algorithm in this context might in fact be
// a pseudonym - for cryptographical signing algorithms that require the
// signed data to be hashed first, these names commonly refer to the
// combination of that signing algorithm and the hash algorithm.
//
// [IANA Registry]]: https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
// [Varsig Specification]: https://github.com/ChainAgnostic/varsig
package varsig

import (
	"encoding/binary"
	"errors"
	"io"
)

// Varsig represents types that describe how a signature was generated
// and thus how to interpret the signature and verify the signed data.
type Varsig interface {
	// Version returns the varsig's version field.
	Version() Version

	// Discriminator returns the algorithm used to produce the corresponding signature.
	Discriminator() Discriminator

	// PayloadEncoding returns the codec that was used to encode the signed data.
	PayloadEncoding() PayloadEncoding

	// Signature returns the cryptographic signature of the signed data.
	// This value is never present in a varsig >= v1 and must either be a valid
	// signature with the correct length or empty in varsig < v1.
	Signature() []byte

	// Encode returns the encoded byte format of the varsig.
	Encode() []byte
}

// Decode converts the provided data into one of the Varsig types
// provided by the DefaultRegistry.
func Decode(data []byte) (Varsig, error) {
	return DefaultRegistry().Decode(data)
}

// DecodeStream converts data read from the provided io.Reader into one
// of the Varsig types provided by the DefaultRegistry.
func DecodeStream(r BytesReader) (Varsig, error) {
	return DefaultRegistry().DecodeStream(r)
}

type varsig struct {
	vers   Version
	disc   Discriminator
	payEnc PayloadEncoding
	sig    []byte
}

// Version returns the varsig's version field.
func (v varsig) Version() Version {
	return v.vers
}

// Discriminator returns the algorithm used to produce the corresponding
// signature.
func (v varsig) Discriminator() Discriminator {
	return v.disc
}

// PayloadEncoding returns the codec that was used to encode the signed
// data.
func (v varsig) PayloadEncoding() PayloadEncoding {
	return v.payEnc
}

// Signature returns the cryptographic signature of the signed data. This
// value is never present in a varsig >= v1 and must either be a valid
// signature with the correct length or empty in varsig < v1.
func (v varsig) Signature() []byte {
	return v.sig
}

func (v varsig) encode() []byte {
	var buf []byte

	buf = binary.AppendUvarint(buf, Prefix)

	if v.Version() == Version1 {
		buf = binary.AppendUvarint(buf, uint64(Version1))
	}

	buf = binary.AppendUvarint(buf, uint64(v.disc))

	return buf
}

func (v varsig) decodePayEncAndSig(r BytesReader) (PayloadEncoding, []byte, error) {
	payEnc, err := DecodePayloadEncoding(r, v.Version())
	if err != nil {
		return 0, nil, err
	}

	var signature []byte
	switch v.Version() {
	case Version0:
		signature, err = io.ReadAll(r)
		if err != nil {
			return 0, nil, err
		}
	case Version1:
		_, err := r.ReadByte()
		if err != nil && !errors.Is(err, io.EOF) {
			return 0, nil, err
		}
		if err == nil {
			return 0, nil, ErrUnexpectedSignaturePresent
		}
	default:
		return 0, nil, ErrUnsupportedVersion
	}

	return payEnc, signature, nil
}

func validateSig[T Varsig](v T, expectedLength uint64) (T, error) {
	if v.Version() == Version0 && len(v.Signature()) == 0 {
		return v, ErrMissingSignature
	}

	if v.Version() == Version0 && uint64(len(v.Signature())) != expectedLength {
		return *new(T), ErrUnexpectedSignatureSize
	}

	if v.Version() == Version1 && len(v.Signature()) != 0 {
		return *new(T), ErrUnexpectedSignaturePresent
	}

	return v, nil
}

type BytesReader interface {
	io.ByteReader
	io.Reader
}
