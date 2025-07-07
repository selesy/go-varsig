package varsig_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/selesy/go-varsig"
)

func TestRegistry_Decode(t *testing.T) {
	t.Parallel()

	t.Run("passes - v0", func(t *testing.T) {
		t.Parallel()

		data, err := hex.DecodeString("348120")
		require.NoError(t, err)

		reg := testRegistry(t)

		vs, err := reg.DecodeStream(bytes.NewReader(data))
		require.NoError(t, err)
		assert.Equal(t, varsig.Version0, vs.Version())
		assert.Equal(t, testSignAlgorithm1, vs.SignatureAlgorithm())
	})

	t.Run("passes - v1", func(t *testing.T) {
		t.Parallel()

		data, err := hex.DecodeString("34018120")
		require.NoError(t, err)

		reg := testRegistry(t)

		vs, err := reg.DecodeStream(bytes.NewReader(data))
		require.NoError(t, err)
		assert.Equal(t, varsig.Version1, vs.Version())
		assert.Equal(t, testSignAlgorithm1, vs.SignatureAlgorithm())
	})
}

const (
	testSignAlgorithm0 varsig.SignAlgorithm = 0x1000
	testSignAlgorithm1 varsig.SignAlgorithm = 0x1001
)

func testRegistry(t *testing.T) varsig.Registry {
	t.Helper()

	reg := varsig.NewRegistry()
	reg.Register(testSignAlgorithm0, testParseFunc(t))
	reg.Register(testSignAlgorithm1, testParseFunc(t))

	return reg
}

func testParseFunc(t *testing.T) varsig.ParseFunc {
	t.Helper()

	return func(r *bytes.Reader, vers varsig.Version, signAlg varsig.SignAlgorithm) (varsig.Varsig, error) {
		v := &testVarsig{
			vers:    vers,
			signAlg: signAlg,
		}

		return v, nil
	}
}

var _ varsig.Varsig = (*testVarsig)(nil)

type testVarsig struct {
	vers    varsig.Version
	signAlg varsig.SignAlgorithm
	payEnc  varsig.PayloadEncoding
	sig     []byte
}

func (v *testVarsig) Version() varsig.Version {
	return v.vers
}

func (v *testVarsig) SignatureAlgorithm() varsig.SignAlgorithm {
	return v.signAlg
}

func (v *testVarsig) PayloadEncoding() varsig.PayloadEncoding {
	return v.payEnc
}

func (v *testVarsig) Signature() []byte {
	return v.sig
}

func (v *testVarsig) Encode() []byte {
	return nil
}
