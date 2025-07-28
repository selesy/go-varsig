package varsig

import "errors"

// ErrNotYetImplemented is returned when a function is currently under
// construction.  For released versions of this library, this error should
// never occur.
var ErrNotYetImplemented = errors.New("not yet implemented")

// ErrUnknownHash is returned when an unexpected value is provided
// while decoding the hashing algorithm.
var ErrUnknownHash = errors.New("unknown hash algorithm")

// ErrUnsupportedPayloadEncoding is returned when an unexpected value is
// provided while decoding the payload encoding field.  The allowed values
// for this field may vary based on the varsig version.
var ErrUnsupportedPayloadEncoding = errors.New("unsupported payload encoding")

// ErrUnknownDiscriminator is returned when the Registry doesn't have a
// parsing function for the decoded signing algorithm.
var ErrUnknownDiscriminator = errors.New("unknown signing algorithm")

// ErrUnknownEdDSACurve is returned when the decoded uvarint isn't either
// CurveEd25519 or CurveEd448.
var ErrUnknownEdDSACurve = errors.New("unknown Edwards curve")

// ErrUnknownECDSACurve is returned when the decoded uvarint isn't either
// CurveSecp256k1, CurveP256, CurveP384 or CurveP521.
var ErrUnknownECDSACurve = errors.New("unknown ECDSA curve")

// ErrUnsupportedVersion is returned when an unsupported varsig version
// field is present.
var ErrUnsupportedVersion = errors.New("unsupported version")

// ErrBadPrefix is returned when the prefix field contains a value other
// than 0x34 (encoded as an uvarint).
var ErrBadPrefix = errors.New("varsig prefix not found")
