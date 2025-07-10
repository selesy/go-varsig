package varsig

import (
	"encoding/binary"
	"fmt"
)

// Prefix is the value for the varsig's varuint prefix byte.
const Prefix = uint64(0x34)

// HashAlgorithm is the value that specifies the hash algorithm
// that's used to reduce the signed content
type HashAlgorithm uint64

// Constant values that allow Varsig implementations to specify how
// the payload content is hashed before the signature is generated.
const (
	HashAlgorithmUnspecified HashAlgorithm = 0x00
	HashAlgorithmSHA256                    = HashAlgorithm(0x12)
	HashAlgorithmSHA384                    = HashAlgorithm(0x20)
	HashAlgorithmSHA512                    = HashAlgorithm(0x13)
	HashAlgorithmShake256                  = HashAlgorithm(0x19)
)

// DecodeHashAlgorithm reads and validates the expected hash algorithm
// (for varsig types include a variable hash algorithm.)
func DecodeHashAlgorithm(r BytesReader) (HashAlgorithm, error) {
	u, err := binary.ReadUvarint(r)
	if err != nil {
		return HashAlgorithmUnspecified, fmt.Errorf("%w: %w", ErrUnknownHashAlgorithm, err)
	}

	h := HashAlgorithm(u)

	switch h {
	case HashAlgorithmSHA256,
		HashAlgorithmSHA384,
		HashAlgorithmSHA512,
		HashAlgorithmShake256:
		return h, nil
	default:
		return HashAlgorithmUnspecified, fmt.Errorf("%w: %x", ErrUnknownHashAlgorithm, h)
	}
}

// PayloadEncoding specifies the encoding of the data being (hashed and)
// signed.  A canonical representation of the data is required to produce
// consistent hashes and signatures.
type PayloadEncoding uint64

// Constant values that allow Varsig implementations to specify how the
// payload content is encoded before being hashed.
// In varsig >= v1, only canonical encoding is allowed.
const (
	PayloadEncodingUnspecified PayloadEncoding = 0x00
	PayloadEncodingVerbatim    PayloadEncoding = 0x5f
	PayloadEncodingDAGPB                       = PayloadEncoding(0x70)
	PayloadEncodingDAGCBOR                     = PayloadEncoding(0x71)
	PayloadEncodingDAGJSON                     = PayloadEncoding(0x0129)
	PayloadEncodingEIP191                      = PayloadEncoding(0xd191)
	PayloadEncodingJWT         PayloadEncoding = 0x6a77
)

// DecodePayloadEncoding reads and validates the expected canonical payload
// encoding of the data to be signed.
func DecodePayloadEncoding(r BytesReader, vers Version) (PayloadEncoding, error) {
	u, err := binary.ReadUvarint(r)
	if err != nil {
		return PayloadEncodingUnspecified, fmt.Errorf("%w: %w", ErrUnsupportedPayloadEncoding, err)
	}

	payEnc := PayloadEncoding(u)

	switch vers {
	case Version0:
		return decodeEncodingInfoV0(payEnc)
	case Version1:
		return decodeEncodingInfoV1(payEnc)
	default:
		return 0, ErrUnsupportedVersion
	}
}

// https://github.com/ChainAgnostic/varsig#4-payload-encoding
func decodeEncodingInfoV0(payEnc PayloadEncoding) (PayloadEncoding, error) {
	switch payEnc {
	case PayloadEncodingVerbatim,
		PayloadEncodingDAGPB,
		PayloadEncodingDAGCBOR,
		PayloadEncodingDAGJSON,
		PayloadEncodingJWT,
		PayloadEncodingEIP191:
		return payEnc, nil
	default:
		return PayloadEncodingUnspecified, fmt.Errorf("%w: version=%d, encoding=%x", ErrUnsupportedPayloadEncoding, Version0, payEnc)
	}
}

// https://github.com/expede/varsig/blob/main/README.md#payload-encoding
func decodeEncodingInfoV1(payEnc PayloadEncoding) (PayloadEncoding, error) {
	switch payEnc {
	case PayloadEncodingVerbatim,
		PayloadEncodingDAGCBOR,
		PayloadEncodingDAGJSON,
		PayloadEncodingEIP191:
		return payEnc, nil
	default:
		return PayloadEncodingUnspecified, fmt.Errorf("%w: version=%d, encoding=%x", ErrUnsupportedPayloadEncoding, Version1, payEnc)
	}
}

// Discriminator is (usually) the value representing the public key type of
// the algorithm used to create the signature.
//
// There is not set list of constants here, nor is there a decode function
// as the author of an implementation should include the constant with the
// implementation, and the decoding is handled by the Handler, which uses
// the Discriminator to choose the correct implementation.  Also note that
// some of the Discriminator values for a specific implementation have
// changed between varsig v0 and v1, so it's possible to have more than one
// constant defined per implementation.
type Discriminator uint64
