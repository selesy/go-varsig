package varsig

// Ed25519 produces a varsig that describes the associated algorithm defined
// by the [IANA JOSE specification].
//
// [IANA JOSE specification]: https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
func Ed25519(payloadEncoding PayloadEncoding, opts ...Option) (EdDSAVarsig, error) {
	return NewEdDSAVarsig(CurveEd25519, HashAlgorithmSHA512, payloadEncoding, opts...)
}

// Ed448 produces a varsig that describes the associated algorithm defined
// by the [IANA JOSE specification].
//
// [IANA JOSE specification]: https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
func Ed448(payloadEncoding PayloadEncoding, opts ...Option) (EdDSAVarsig, error) {
	return NewEdDSAVarsig(CurveEd448, HashAlgorithmShake256, payloadEncoding, opts...)
}

// RS256 produces a varsig that describes the associated algorithm defined
// by the [IANA JOSE specification].
//
// [IANA JOSE specification]: https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
func RS256(keyLength uint64, payloadEncoding PayloadEncoding, opts ...Option) (RSAVarsig, error) {
	return NewRSAVarsig(HashAlgorithmSHA256, keyLength, payloadEncoding, opts...)
}

// RS384 produces a varsig that describes the associated algorithm defined
// by the [IANA JOSE specification].
//
// [IANA JOSE specification]: https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
func RS384(keyLength uint64, payloadEncoding PayloadEncoding, opts ...Option) (RSAVarsig, error) {
	return NewRSAVarsig(HashAlgorithmSHA384, keyLength, payloadEncoding, opts...)
}

// RS512 produces a varsig that describes the associated algorithm defined
// by the [IANA JOSE specification].
//
// [IANA JOSE specification]: https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
func RS512(keyLength uint64, payloadEncoding PayloadEncoding, opts ...Option) (RSAVarsig, error) {
	return NewRSAVarsig(HashAlgorithmSHA512, keyLength, payloadEncoding, opts...)
}
