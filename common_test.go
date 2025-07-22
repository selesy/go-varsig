package varsig_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ucan-wg/go-varsig"
)

func TestEd25519(t *testing.T) {
	t.Parallel()

	in, err := varsig.Ed25519(varsig.PayloadEncodingDAGCBOR)
	mustVarsig(t, in, err)
	out := roundTrip(t, in, "3401ed01ed011371")
	assertEdDSAEqual(t, in, out)
}

func TestEd448(t *testing.T) {
	t.Parallel()

	in, err := varsig.Ed448(varsig.PayloadEncodingDAGCBOR)
	mustVarsig(t, in, err)
	out := roundTrip(t, in, "3401ed0183241971")
	assertEdDSAEqual(t, in, out)
}

func TestRS256(t *testing.T) {
	t.Parallel()

	in, err := varsig.RS256(0x100, varsig.PayloadEncodingDAGCBOR)
	mustVarsig(t, in, err)
	out := roundTrip(t, in, "3401852412800271")
	assertRSAEqual(t, in, out)
}

func TestRS384(t *testing.T) {
	t.Parallel()

	in, err := varsig.RS384(0x100, varsig.PayloadEncodingDAGCBOR)
	mustVarsig(t, in, err)
	out := roundTrip(t, in, "3401852420800271")
	assertRSAEqual(t, in, out)
}

func TestRS512(t *testing.T) {
	t.Parallel()

	in, err := varsig.RS512(0x100, varsig.PayloadEncodingDAGCBOR)
	mustVarsig(t, in, err)
	out := roundTrip(t, in, "3401852413800271")
	assertRSAEqual(t, in, out)
}

func assertEdDSAEqual(t *testing.T, in, out varsig.EdDSAVarsig) {
	t.Helper()

	assert.Equal(t, in.Curve(), out.Curve())
	assert.Equal(t, in.Hash(), out.Hash())
}

func assertRSAEqual(t *testing.T, in, out varsig.RSAVarsig) {
	t.Helper()

	assert.Equal(t, in.Hash(), out.Hash())
	assert.Equal(t, in.KeyLength(), out.KeyLength())
}
