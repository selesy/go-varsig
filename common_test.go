package varsig_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/selesy/go-varsig"
)

func TestRS256(t *testing.T) {
	t.Parallel()

	in := mustVarsig[varsig.RSAVarsig](t)(varsig.RS256(0x100, varsig.PayloadEncodingDAGCBOR))
	out := roundTrip(t, in, "NAGFJBKAAnE")
	assertRSAEqual(t, in, out)
}

func TestRS384(t *testing.T) {
	t.Parallel()

	in := mustVarsig[varsig.RSAVarsig](t)(varsig.RS384(0x100, varsig.PayloadEncodingDAGCBOR))
	out := roundTrip(t, in, "NAGFJCCAAnE")
	assertRSAEqual(t, in, out)
}

func TestRS512(t *testing.T) {
	t.Parallel()

	in := mustVarsig[varsig.RSAVarsig](t)(varsig.RS512(0x100, varsig.PayloadEncodingDAGCBOR))
	out := roundTrip(t, in, "NAGFJBOAAnE")
	assertRSAEqual(t, in, out)
}

func assertRSAEqual(t *testing.T, in, out *varsig.RSAVarsig) {
	t.Helper()

	assert.Equal(t, in.HashAlgorithm(), out.HashAlgorithm())
	assert.Equal(t, in.KeyLength(), out.KeyLength())
}
