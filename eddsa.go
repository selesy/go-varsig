package varsig

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"

	"github.com/multiformats/go-multicodec"
)

// Constants containing multicodec.Code values that specify EdDSA signatures.
const (
	DiscriminatorEdDSA   = Discriminator(multicodec.Ed25519Pub)
	DiscriminatorEd25519 = Discriminator(multicodec.Ed25519Pub)
	DiscriminatorEd448   = Discriminator(multicodec.Ed448Pub)
)

// EdDSACurve are multicodec.Code values that specify which Edwards curve
// is used when generating the signature.
type EdDSACurve uint64

// Constants describing the multicodec.Code for each specific Edwards
// curve that can be encoded into a Varsig.
const (
	CurveEd25519 = EdDSACurve(multicodec.Ed25519Pub)
	CurveEd448   = EdDSACurve(multicodec.Ed448Pub)
)

var _ Varsig = (*EdDSAVarsig)(nil)

// EdDSAVarsig is a varsig that encodes the parameters required to describe
// an EdDSA signature.
type EdDSAVarsig struct {
	varsig[EdDSAVarsig]

	curve   EdDSACurve
	hashAlg HashAlgorithm
}

// NewEdDSAVarsig creates and validates an EdDSA varsig with the provided
// curve, hash algorithm and payload encoding.
func NewEdDSAVarsig(curve EdDSACurve, hashAlgorithm HashAlgorithm, payloadEncoding PayloadEncoding, opts ...Option) (*EdDSAVarsig, error) {
	options := newOptions(opts...)

	var (
		vers = Version1
		disc = DiscriminatorEdDSA
		sig  = []byte{}
	)

	if options.ForceVersion0() {
		vers = Version0
		disc = Discriminator(curve)
		sig = options.Signature()
	}

	v := &EdDSAVarsig{
		varsig: varsig[EdDSAVarsig]{
			vers:   vers,
			disc:   disc,
			payEnc: payloadEncoding,
			sig:    sig,
		},
		curve:   curve,
		hashAlg: hashAlgorithm,
	}

	return v.validateSig(v, ed25519.PrivateKeySize)
}

// Curve returns the Edwards curve used to generate the EdDSA signature.
func (v *EdDSAVarsig) Curve() EdDSACurve {
	return v.curve
}

// HashAlgorithm returns the multicodec.Code describing the hash algorithm
// used to hash the payload content before the signature is generated.
func (v *EdDSAVarsig) HashAlgorithm() HashAlgorithm {
	return v.hashAlg
}

// Encode returns the encoded byte format of the EdDSAVarsig.
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

func decodeEd25519(r *bytes.Reader, vers Version, disc Discriminator) (Varsig, error) {
	curve := uint64(disc)
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
			vers: vers,
			disc: disc,
		},
		curve:   EdDSACurve(curve),
		hashAlg: HashAlgorithm(hashAlg),
	}

	return v.decodePayEncAndSig(r, v, ed25519.PrivateKeySize)
}
