package varsig

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/multiformats/go-multicodec"
)

// Prefix is the multicodec.Code for the varsig's varuint prefix byte.
const Prefix = uint64(multicodec.Varsig)

// HashAlgorithm is the multicodec.Code that specifies the hash algorithm
// that's used to reduced the signed content
type HashAlgorithm uint64

// Constant multicodec.Code values that allow Varsig implementations to
// specify how the payload content is hashed before the signature is
// generated.
const (
	HashAlgorithmUnspecified HashAlgorithm = 0x00
	HashAlgorithmSHA256                    = HashAlgorithm(multicodec.Sha2_256)
	HashAlgorithmSHA384                    = HashAlgorithm(multicodec.Sha2_384)
	HashAlgorithmSHA512                    = HashAlgorithm(multicodec.Sha2_512)
	HashAlgorithmShake256                  = HashAlgorithm(multicodec.Shake256)
)

// DecodeHashAlgorithm reads and validates the expected hash algorithm
// (for varsig types include a variable hash algorithm.)
func DecodeHashAlgorithm(r *bytes.Reader) (HashAlgorithm, error) {
	u, err := binary.ReadUvarint(r)
	if err != nil {
		return HashAlgorithmUnspecified, fmt.Errorf("%w: %w", ErrUnknownHashAlgorithm, err)
	}

	h := HashAlgorithm(u)

	if _, ok := map[HashAlgorithm]struct{}{
		HashAlgorithmSHA256:   {},
		HashAlgorithmSHA384:   {},
		HashAlgorithmSHA512:   {},
		HashAlgorithmShake256: {},
	}[h]; !ok {
		return HashAlgorithmUnspecified, fmt.Errorf("%w: %x", ErrUnknownHashAlgorithm, h)
	}

	return h, nil
}

// PayloadEncoding specifies the encoding of the data being (hashed and)
// signed.  A canonical representation of the data is required to produce
// consistent hashes and signatures.
type PayloadEncoding uint64

// Constant multicodec.Code values that allow Varsig implementations to
// specify how the payload content is encoded before being hashed.  In
// varsig >= v1, only canonical encoding is allowed.
const (
	PayloadEncodingUnspecified PayloadEncoding = 0x00
	PayloadEncodingVerbatim    PayloadEncoding = 0x5f
	PayloadEncodingDAGPB                       = PayloadEncoding(multicodec.DagPb)
	PayloadEncodingDAGCBOR                     = PayloadEncoding(multicodec.DagCbor)
	PayloadEncodingDAGJSON                     = PayloadEncoding(multicodec.DagJson)
	PayloadEncodingEIP191                      = PayloadEncoding(multicodec.Eip191)
	PayloadEncodingJWT         PayloadEncoding = 0x6a77
)

// DecodePayloadEncoding reads and validates the expected canonical payload
// encoding of the data to be signed.
func DecodePayloadEncoding(r *bytes.Reader, vers Version) (PayloadEncoding, error) {
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
	if _, ok := map[PayloadEncoding]struct{}{
		PayloadEncodingVerbatim: {},
		PayloadEncodingDAGPB:    {},
		PayloadEncodingDAGCBOR:  {},
		PayloadEncodingDAGJSON:  {},
		PayloadEncodingJWT:      {},
		PayloadEncodingEIP191:   {},
	}[payEnc]; !ok {
		return PayloadEncodingUnspecified, fmt.Errorf("%w: version=%d, encoding=%x", ErrUnsupportedPayloadEncoding, Version0, payEnc)
	}

	return payEnc, nil
}

// https://github.com/expede/varsig/blob/main/README.md#payload-encoding
func decodeEncodingInfoV1(payEnc PayloadEncoding) (PayloadEncoding, error) {
	if _, ok := map[PayloadEncoding]struct{}{
		PayloadEncodingVerbatim: {},
		PayloadEncodingDAGCBOR:  {},
		PayloadEncodingDAGJSON:  {},
		PayloadEncodingEIP191:   {},
	}[payEnc]; !ok {
		return PayloadEncodingUnspecified, fmt.Errorf("%w: version=%d, encoding=%x", ErrUnsupportedPayloadEncoding, Version1, payEnc)
	}

	return payEnc, nil
}

// Discriminator is (usually) the multicodec.Code representing the public
// key type of the algorithm used to create the signature.
//
// There is not set list of constants here, nor is there a decode function
// as the author of an implementation should include the constant with the
// implementation, and the decoding is handled by the Handler, which uses
// the Discriminator to choose the correct implementation.  Also note that
// some of the Discriminator values for a specific implementation have
// changed between varsig v0 and v1, so it's possible to have more than one
// constant defined per implementation.
type Discriminator uint64
