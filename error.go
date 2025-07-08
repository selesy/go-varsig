package varsig

import "errors"

// ErrMissingSignature is returned when a varsig v0 is parsed and does
// not contain the expected signature bytes.  This is expected in some
// intermediate cases, such as the UCAN v1 specification.
var ErrMissingSignature = errors.New("missing signature expected in varsig v0")

// ErrNotYetImplemented is returned when a function is currently under
// construction.  For released versions of this library, this error should
// never occur.
var ErrNotYetImplemented = errors.New("not yet implemented")

// ErrUnexpectedSignaturePresent is returned when a signature is present
// in  a varsig >= v1.
var ErrUnexpectedSignaturePresent = errors.New("unexpected signature present in varsig >= v1")

// ErrUnexpectedSignatureSize is returned when the length of the decoded
// signature doesn't match the expected signature length as defined by the
// signing algorithm or sent via a Varsig field.
var ErrUnexpectedSignatureSize = errors.New("unexpected signature size in varsig v0")

// ErrUnknownHashAlgoritm is returned when an unexpected value is provided
// while decoding the hashing algorithm.
var ErrUnknownHashAlgorithm = errors.New("unknown hash algorithm")

// ErrUnsupportedPayloadEncoding is returned when an unexpected value is
// provided while decoding the payload encoding field.  The allowed values
// for this field may vary based on the varsig version.
var ErrUnsupportedPayloadEncoding = errors.New("unsupported payload encoding")

// ErrUnknowndiscorith is returned when the Registry doesn't have a
// parsing function for the decoded signing algorithm.
var ErrUnknownDiscriminator = errors.New("unknown signing algorithm")

// ErrUnknownEdDSACurve is returned when the decoded uvarint isn't either
// CurveEd25519 or CurveEd448.
var ErrUnknownEdDSACurve = errors.New("unknown Edwards curve")

// ErrUnsupportedVersion is returned when an unsupported varsig version
// field is present.
var ErrUnsupportedVersion = errors.New("unsupported version")

// ErrBadPrefix is returned when the prefix field contains a value other
// than 0x34 (encoded as a uvarint).
var ErrBadPrefix = errors.New("varsig prefix not found")
