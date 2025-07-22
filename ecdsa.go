package varsig

import (
	"encoding/binary"
	"fmt"
)

// DiscriminatorECDSA is the value specifying an ECDSA signature.
const DiscriminatorECDSA = Discriminator(0xec)

// ECDSACurve are values that specify which ECDSA curve is used when
// generating the signature.
type ECDSACurve uint64

// Constants describing the values for each specific ECDSA curve that can
// be encoded into a Varsig.
const (
	CurveSecp256k1 = ECDSACurve(0xe7)
	CurveP256      = ECDSACurve(0x1200)
	CurveP384      = ECDSACurve(0x1201)
	CurveP521      = ECDSACurve(0x1202)
)

func decodeECDSACurve(r BytesReader) (ECDSACurve, error) {
	u, err := binary.ReadUvarint(r)
	if err != nil {
		return 0, err
	}

	switch curve := ECDSACurve(u); curve {
	case CurveSecp256k1, CurveP256, CurveP384, CurveP521:
		return curve, nil
	default:
		return 0, fmt.Errorf("%w: %x", ErrUnknownECDSACurve, u)
	}
}

var _ Varsig = ECDSAVarsig{}

// ECDSAVarsig is a varsig that encodes the parameters required to describe
// an ECDSA signature.
type ECDSAVarsig struct {
	varsig

	curve   ECDSACurve
	hashAlg Hash
}

// NewECDSAVarsig creates and validates an ECDSA varsig with the provided
// curve, hash algorithm and payload encoding.
func NewECDSAVarsig(curve ECDSACurve, hashAlgorithm Hash, payloadEncoding PayloadEncoding, opts ...Option) (ECDSAVarsig, error) {
	options := newOptions(opts...)

	var (
		vers = Version1
		disc = DiscriminatorECDSA
		sig  []byte
	)

	if options.ForceVersion0() {
		vers = Version0
		disc = Discriminator(curve)
		sig = options.Signature()
	}

	v := ECDSAVarsig{
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
	case CurveSecp256k1, CurveP256:
		return validateSig(v, 64)
	case CurveP384:
		return validateSig(v, 96)
	case CurveP521:
		return validateSig(v, 132)
	default:
		return ECDSAVarsig{}, fmt.Errorf("%w: %x", ErrUnknownECDSACurve, curve)
	}
}

// Curve returns the elliptic curve used to generate the ECDSA signature.
func (v ECDSAVarsig) Curve() ECDSACurve {
	return v.curve
}

// Hash returns the value describing the hash algorithm used to hash
// the payload content before the signature is generated.
func (v ECDSAVarsig) Hash() Hash {
	return v.hashAlg
}

// Encode returns the encoded byte format of the ECDSAVarsig.
func (v ECDSAVarsig) Encode() []byte {
	buf := v.encode()

	if v.vers != Version0 {
		buf = binary.AppendUvarint(buf, uint64(v.curve))
	}

	buf = binary.AppendUvarint(buf, uint64(v.hashAlg))
	buf = binary.AppendUvarint(buf, uint64(v.payEnc))
	buf = append(buf, v.Signature()...)

	return buf
}

func decodeECDSA(r BytesReader, vers Version, disc Discriminator) (Varsig, error) {
	curve := ECDSACurve(disc)
	if vers != Version0 {
		var err error

		curve, err = decodeECDSACurve(r)
		if err != nil {
			return nil, err
		}
	}

	hashAlg, err := DecodeHashAlgorithm(r)
	if err != nil {
		return nil, err
	}

	v := ECDSAVarsig{
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
	case CurveSecp256k1, CurveP256:
		return validateSig(v, 64)
	case CurveP384:
		return validateSig(v, 96)
	case CurveP521:
		return validateSig(v, 132)
	default:
		return ECDSAVarsig{}, fmt.Errorf("%w: %x", ErrUnknownECDSACurve, curve)
	}
}
