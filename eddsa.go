package varsig

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"

	"github.com/multiformats/go-multicodec"
)

const (
	SignAlgorithmEdDSA   = SignAlgorithm(multicodec.Ed25519Pub)
	SignAlgorithmEd25519 = SignAlgorithm(multicodec.Ed25519Pub)
	SignAlgorithmEd448   = SignAlgorithm(multicodec.Ed448Pub)
)

type EdDSACurve uint64

const (
	CurveEd25519 = EdDSACurve(multicodec.Ed25519Pub)
	CurveEd448   = EdDSACurve(multicodec.Ed448Pub)
)

var _ Varsig = (*EdDSAVarsig)(nil)

type EdDSAVarsig struct {
	varsig[EdDSAVarsig]

	curve   EdDSACurve
	hashAlg HashAlgorithm
}

func NewEdDSAVarsig(curve EdDSACurve, hashAlgorithm HashAlgorithm, payloadEncoding PayloadEncoding, opts ...Option) (*EdDSAVarsig, error) {
	options := newOptions(opts...)

	var (
		vers    = Version1
		signAlg = SignAlgorithmEdDSA
		sig     = []byte{}
	)

	if options.ForceVersion0() {
		vers = Version0
		signAlg = SignAlgorithm(curve)
		sig = options.Signature()
	}

	v := &EdDSAVarsig{
		varsig: varsig[EdDSAVarsig]{
			vers:    vers,
			signAlg: signAlg,
			payEnc:  payloadEncoding,
			sig:     sig,
		},
		curve:   curve,
		hashAlg: hashAlgorithm,
	}

	return v.validateSig(v, ed25519.PrivateKeySize)
}

func (v *EdDSAVarsig) Curve() EdDSACurve {
	return v.curve
}

func (v *EdDSAVarsig) HashAlgorithm() HashAlgorithm {
	return v.hashAlg
}

func (v EdDSAVarsig) Encode() []byte {
	buf := v.encode()

	if v.vers != Version0 {
		buf = binary.AppendUvarint(buf, uint64(v.curve))
	}

	buf = binary.AppendUvarint(buf, uint64(v.hashAlg))
	buf = binary.AppendUvarint(buf, uint64(v.payEnc))
	buf = append(buf, v.Signature()...)

	return buf
}

func decodeEd25519(r *bytes.Reader, vers Version, signAlg SignAlgorithm) (Varsig, error) {
	curve := uint64(signAlg)
	if vers != Version0 {
		u, err := binary.ReadUvarint(r)

		if err != nil {
			return nil, err // TODO: wrap error?
		}

		curve = u
	}

	hashAlg, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err // TODO: wrap error?
	}

	v := &EdDSAVarsig{
		varsig: varsig[EdDSAVarsig]{
			vers:    vers,
			signAlg: signAlg,
		},
		curve:   EdDSACurve(curve),
		hashAlg: HashAlgorithm(hashAlg),
	}

	return v.decodePayEncAndSig(r, v, ed25519.PrivateKeySize)
}

// TODO: remove this when parseEd25519 is added to the DefaultRegistry.
func Junk() {
	_, _ = decodeEd25519(nil, 0, 0)
}
