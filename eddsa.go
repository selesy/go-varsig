package varsig

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
)

// DiscriminatorEdDSA is the value specifying an EdDSA signature.
const DiscriminatorEdDSA = Discriminator(0xed)

// EdDSACurve are values that specify which Edwards curve is used when
// generating the signature.
type EdDSACurve uint64

// Constants describing the values for each specific Edwards curve that can
// be encoded into a Varsig.
const (
	CurveEd25519 = EdDSACurve(0xed)
	CurveEd448   = EdDSACurve(0x1203)
)

func decodeEdDSACurve(r BytesReader) (EdDSACurve, error) {
	u, err := binary.ReadUvarint(r)
	if err != nil {
		return 0, err
	}

	switch curve := EdDSACurve(u); curve {
	case CurveEd25519, CurveEd448:
		return curve, nil
	default:
		return 0, fmt.Errorf("%w: %x", ErrUnknownEdDSACurve, u)
	}
}

var _ Varsig = EdDSAVarsig{}

// EdDSAVarsig is a varsig that encodes the parameters required to describe
// an EdDSA signature.
type EdDSAVarsig struct {
	varsig

	curve   EdDSACurve
	hashAlg Hash
}

// NewEdDSAVarsig creates and validates an EdDSA varsig with the provided
// curve, hash algorithm and payload encoding.
func NewEdDSAVarsig(curve EdDSACurve, hashAlgorithm Hash, payloadEncoding PayloadEncoding, opts ...Option) (EdDSAVarsig, error) {
	options := newOptions(opts...)

	var (
		vers = Version1
		disc = DiscriminatorEdDSA
		sig  []byte
	)

	if options.ForceVersion0() {
		vers = Version0
		disc = Discriminator(curve)
		sig = options.Signature()
	}

	v := EdDSAVarsig{
		varsig: varsig{
			vers:   vers,
			disc:   disc,
			payEnc: payloadEncoding,
			sig:    sig,
		},
		curve:   curve,
		hashAlg: hashAlgorithm,
	}

	switch curve {
	case CurveEd25519:
		return validateSig(v, ed25519.SignatureSize)
	case CurveEd448:
		return validateSig(v, 114)
	default:
		return EdDSAVarsig{}, fmt.Errorf("%w: %x", ErrUnknownEdDSACurve, curve)
	}
}

// Curve returns the Edwards curve used to generate the EdDSA signature.
func (v EdDSAVarsig) Curve() EdDSACurve {
	return v.curve
}

// Hash returns the value describing the hash algorithm used to hash
// the payload content before the signature is generated.
func (v EdDSAVarsig) Hash() Hash {
	return v.hashAlg
}

// Encode returns the encoded byte format of the EdDSAVarsig.
func (v EdDSAVarsig) Encode() []byte {
	buf := v.encode()

	if v.vers != Version0 {
		buf = binary.AppendUvarint(buf, uint64(v.curve))
	}

	buf = binary.AppendUvarint(buf, uint64(v.hashAlg))
	buf = append(buf, EncodePayloadEncoding(v.payEnc)...)
	buf = append(buf, v.Signature()...)

	return buf
}

func decodeEdDSA(r BytesReader, vers Version, disc Discriminator) (Varsig, error) {
	curve := EdDSACurve(disc)
	if vers != Version0 {
		var err error

		curve, err = decodeEdDSACurve(r)
		if err != nil {
			return nil, err
		}
	}

	hashAlg, err := DecodeHashAlgorithm(r)
	if err != nil {
		return nil, err
	}

	v := EdDSAVarsig{
		varsig: varsig{
			vers: vers,
			disc: disc,
		},
		curve:   curve,
		hashAlg: hashAlg,
	}

	v.payEnc, v.sig, err = v.decodePayEncAndSig(r)
	if err != nil {
		return nil, err
	}

	switch curve {
	case CurveEd25519:
		return validateSig(v, ed25519.SignatureSize)
	case CurveEd448:
		return validateSig(v, 114)
	default:
		return EdDSAVarsig{}, fmt.Errorf("%w: %x", ErrUnknownEdDSACurve, curve)
	}
}
