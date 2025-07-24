package varsig

import (
	"encoding/binary"
)

// DiscriminatorRSA is the value specifying an RSA signature.
const DiscriminatorRSA = Discriminator(0x1205)

var _ Varsig = RSAVarsig{}

// RSAVarsig is a varsig that encodes the parameters required to describe
// an RSA signature.
type RSAVarsig struct {
	varsig
	hashAlg Hash
	sigLen  uint64
}

// NewRSAVarsig creates and validates an RSA varsig with the provided
// hash algorithm, key length and payload encoding.
func NewRSAVarsig(hashAlgorithm Hash, keyLength uint64, payloadEncoding PayloadEncoding, opts ...Option) (RSAVarsig, error) {
	options := newOptions(opts...)

	var (
		vers = Version1
		sig  []byte
	)

	if options.ForceVersion0() {
		vers = Version0
		sig = options.Signature()
	}

	v := RSAVarsig{
		varsig: varsig{
			vers:   vers,
			disc:   DiscriminatorRSA,
			payEnc: payloadEncoding,
			sig:    sig,
		},
		hashAlg: hashAlgorithm,
		sigLen:  keyLength,
	}

	return validateSig(v, v.sigLen)
}

// Encode returns the encoded byte format of the RSAVarsig.
func (v RSAVarsig) Encode() []byte {
	buf := v.encode()
	buf = binary.AppendUvarint(buf, uint64(v.hashAlg))
	buf = binary.AppendUvarint(buf, v.sigLen)
	buf = append(buf, EncodePayloadEncoding(v.payEnc)...)
	buf = append(buf, v.Signature()...)

	return buf
}

// Hash returns the value describing the hash algorithm used to hash
// the payload content before the signature is generated.
func (v RSAVarsig) Hash() Hash {
	return v.hashAlg
}

// KeyLength returns the length of the RSA key used to sign the payload
// content.
func (v RSAVarsig) KeyLength() uint64 {
	return v.sigLen
}

func decodeRSA(r BytesReader, vers Version, disc Discriminator) (Varsig, error) {
	hashAlg, err := DecodeHashAlgorithm(r)
	if err != nil {
		return nil, err
	}

	sigLen, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}

	vs := RSAVarsig{
		varsig: varsig{
			vers: vers,
			disc: disc,
		},
		hashAlg: hashAlg,
		sigLen:  sigLen,
	}

	vs.payEnc, vs.sig, err = vs.decodePayEncAndSig(r)
	if err != nil {
		return nil, err
	}

	return validateSig(vs, vs.sigLen)
}
