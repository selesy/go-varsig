package varsig

// Options define customization when creating a new Varsig.
type Options struct {
	forceVersion0 bool
	signature     []byte
}

func newOptions(opts ...Option) *Options {
	o := &Options{}

	for _, opt := range opts {
		opt(o)
	}

	return o
}

// ForceVersion0 returns a boolean indicating that a Varsig < v1 should
// be created (which means the encoded Varsig won't have a version field
// and might contain the signature bytes as the last field.)
func (o *Options) ForceVersion0() bool {
	return o.forceVersion0
}

// Signature returns the optional signature bytes when creating a Varsig
// < v1.
func (o *Options) Signature() []byte {
	return o.signature
}

// Option is a function that alters the default behavior of constructors
// that produce implementations of the Varsig type.
type Option func(*Options)

// WithForceVersion0 indicates that a Varsig < v1 should be produced. If
// the signature is a) not nil, b) not empty and c) the correct length
// based on the signing algorithm or signing key, the signature's bytes
// will be appended to the encoded Varsig.
func WithForceVersion0(signature []byte) Option {
	return func(o *Options) {
		o.forceVersion0 = true
		o.signature = signature
	}
}
