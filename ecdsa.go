package varsig

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
