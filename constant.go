package varsig

import (
	"encoding/binary"
	"fmt"
)

// Prefix is the value for the varsig's varuint prefix byte.
const Prefix = uint64(0x34)

// Hash is the value that specifies the hash algorithm
// that's used to reduce the signed content
type Hash uint64

// Constant values that allow Varsig implementations to specify how
// the payload content is hashed before the signature is generated.
const (
	HashUnspecified Hash = 0x00

	HashSha2_224 = Hash(0x1013)
	HashSha2_256 = Hash(0x12)
	HashSha2_384 = Hash(0x20)
	HashSha2_512 = Hash(0x13)

	HashSha3_224 = Hash(0x17)
	HashSha3_256 = Hash(0x16)
	HashSha3_384 = Hash(0x15)
	HashSha3_512 = Hash(0x14)

	HashSha512_224 = Hash(0x1014)
	HashSha512_256 = Hash(0x1015)

	HashBlake2s_256 = Hash(0xb260)
	HashBlake2b_256 = Hash(0xb220)
	HashBlake2b_384 = Hash(0xb230)
	HashBlake2b_512 = Hash(0xb240)

	HashShake_256 = Hash(0x19)

	HashKeccak256 = Hash(0x1b)
	HashKeccak512 = Hash(0x1d)
)

// DecodeHashAlgorithm reads and validates the expected hash algorithm
// (for varsig types include a variable hash algorithm.)
func DecodeHashAlgorithm(r BytesReader) (Hash, error) {
	u, err := binary.ReadUvarint(r)
	if err != nil {
		return HashUnspecified, fmt.Errorf("%w: %w", ErrUnknownHash, err)
	}

	h := Hash(u)

	switch h {
	case HashSha2_224,
		HashSha2_256,
		HashSha2_384,
		HashSha2_512,
		HashSha3_224,
		HashSha3_256,
		HashSha3_384,
		HashSha3_512,
		HashSha512_224,
		HashSha512_256,
		HashBlake2s_256,
		HashBlake2b_256,
		HashBlake2b_384,
		HashBlake2b_512,
		HashShake_256,
		HashKeccak256,
		HashKeccak512:
		return h, nil
	default:
		return HashUnspecified, fmt.Errorf("%w: %x", ErrUnknownHash, h)
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
