package varsig

import "fmt"

// [IANA JOSE specification]: https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms

// Ed25519 produces a varsig for EdDSA using Ed25519 curve.
// This algorithm is defined in [IANA JOSE specification].
func Ed25519(payloadEncoding PayloadEncoding, opts ...Option) (EdDSAVarsig, error) {
	return NewEdDSAVarsig(CurveEd25519, HashSha2_512, payloadEncoding, opts...)
}

// Ed448 produces a varsig for EdDSA using Ed448 curve.
// This algorithm is defined in [IANA JOSE specification].
func Ed448(payloadEncoding PayloadEncoding, opts ...Option) (EdDSAVarsig, error) {
	return NewEdDSAVarsig(CurveEd448, HashShake_256, payloadEncoding, opts...)
}

// RS256 produces a varsig for RSASSA-PKCS1-v1_5 using SHA-256.
// This algorithm is defined in [IANA JOSE specification].
func RS256(keyLength uint64, payloadEncoding PayloadEncoding, opts ...Option) (RSAVarsig, error) {
	return NewRSAVarsig(HashSha2_256, keyLength, payloadEncoding, opts...)
}

// RS384 produces a varsig for RSASSA-PKCS1-v1_5 using SHA-384.
// This algorithm is defined in [IANA JOSE specification].
func RS384(keyLength uint64, payloadEncoding PayloadEncoding, opts ...Option) (RSAVarsig, error) {
	return NewRSAVarsig(HashSha2_384, keyLength, payloadEncoding, opts...)
}

// RS512 produces a varsig for RSASSA-PKCS1-v1_5 using SHA-512.
// This algorithm is defined in [IANA JOSE specification].
func RS512(keyLength uint64, payloadEncoding PayloadEncoding, opts ...Option) (RSAVarsig, error) {
	return NewRSAVarsig(HashSha2_512, keyLength, payloadEncoding, opts...)
}

// ES256 produces a varsig for ECDSA using P-256 and SHA-256.
// This algorithm is defined in [IANA JOSE specification].
func ES256(payloadEncoding PayloadEncoding, opts ...Option) (ECDSAVarsig, error) {
	return NewECDSAVarsig(CurveP256, HashSha2_256, payloadEncoding, opts...)
}

// ES256K produces a varsig for ECDSA using secp256k1 curve and SHA-256.
// This algorithm is defined in [IANA JOSE specification].
func ES256K(payloadEncoding PayloadEncoding, opts ...Option) (ECDSAVarsig, error) {
	return NewECDSAVarsig(CurveSecp256k1, HashSha2_256, payloadEncoding, opts...)
}

// ES384 produces a varsig for ECDSA using P-384 and SHA-384.
// This algorithm is defined in [IANA JOSE specification].
func ES384(payloadEncoding PayloadEncoding, opts ...Option) (ECDSAVarsig, error) {
	return NewECDSAVarsig(CurveP384, HashSha2_384, payloadEncoding, opts...)
}

// ES512 produces a varsig for ECDSA using P-521 and SHA-512.
// This algorithm is defined in [IANA JOSE specification].
func ES512(payloadEncoding PayloadEncoding, opts ...Option) (ECDSAVarsig, error) {
	return NewECDSAVarsig(CurveP521, HashSha2_512, payloadEncoding, opts...)
}

// EIP191 produces a varsig for ECDSA using the Secp256k1 curve, Keccak256 and encoded
// with the "personal_sign" format defined by [EIP191].
// payloadEncoding must be either PayloadEncodingEIP191Raw or PayloadEncodingEIP191Cbor.
// [EIP191]: https://eips.ethereum.org/EIPS/eip-191
func EIP191(payloadEncoding PayloadEncoding, opts ...Option) (ECDSAVarsig, error) {
	switch payloadEncoding {
	case PayloadEncodingEIP191Raw, PayloadEncodingEIP191Cbor:
	default:
		return ECDSAVarsig{}, fmt.Errorf("%w for EIP191: %v", ErrUnsupportedPayloadEncoding, payloadEncoding)
	}

	return NewECDSAVarsig(CurveSecp256k1, HashKeccak256, payloadEncoding, opts...)
}
