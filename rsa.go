package varsig

import (
	"bytes"
	"encoding/binary"

	"github.com/multiformats/go-multicodec"
)

const SignAlgorithmRSA = SignAlgorithm(multicodec.RsaPub)

var _ Varsig = (*RSAVarsig)(nil)

// RSAVarsig is a varsig that encodes the parameters required to describe
// and RSA signature.
type RSAVarsig struct {
	varsig[RSAVarsig]
	hashAlg HashAlgorithm
	sigLen  uint64
}

// NewRSAVarsig creates and validates an RSA varsig with the provided
// parameters.
func NewRSAVarsig(hashAlgorithm HashAlgorithm, keyLength uint64, payloadEncoding PayloadEncoding, opts ...Option) (*RSAVarsig, error) {
	options := newOptions(opts...)

	var (
		vers = Version1
		sig  = []byte{}
	)

	if options.ForceVersion0() {
		vers = Version0
		sig = options.Signature()
	}

	v := &RSAVarsig{
		varsig: varsig[RSAVarsig]{
			vers:    vers,
			signAlg: SignAlgorithmRSA,
			payEnc:  payloadEncoding,
			sig:     sig,
		},
		hashAlg: hashAlgorithm,
		sigLen:  keyLength,
	}

	return v.validateSig(v, v.sigLen)
}

// Encode returns the encoded byte formation of the RSAVarsig.
func (v RSAVarsig) Encode() []byte {
	buf := v.encode()
	buf = binary.AppendUvarint(buf, uint64(v.hashAlg))
	buf = binary.AppendUvarint(buf, v.sigLen)
	buf = binary.AppendUvarint(buf, uint64(v.payEnc))
	buf = append(buf, v.Signature()...)

	return buf
}

// HashAlgorithm returns the hash algorithm used to has the payload content.
func (v *RSAVarsig) HashAlgorithm() HashAlgorithm {
	return v.hashAlg
}

// KeyLength returns the length of the RSA key used to sign the payload
// content.
func (v *RSAVarsig) KeyLength() uint64 {
	return v.sigLen
}

func decodeRSA(r *bytes.Reader, vers Version, signAlg SignAlgorithm) (Varsig, error) {
	hashAlg, err := DecodeHashAlgorithm(r)
	if err != nil {
		return nil, err
	}

	sigLen, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}

	vs := &RSAVarsig{
		varsig: varsig[RSAVarsig]{
			vers:    vers,
			signAlg: signAlg,
		},
		hashAlg: HashAlgorithm(hashAlg),
		sigLen:  sigLen,
	}

	return vs.decodePayEncAndSig(r, vs, sigLen)
}
