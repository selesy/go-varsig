package varsig_test

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/selesy/go-varsig"
)

func TestRegistry_Parse(t *testing.T) {
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

	t.Run("fails - no data (empty prefix)", func(t *testing.T) {
		t.Parallel()

		vs, err := varsig.Decode([]byte{})
		require.ErrorIs(t, err, io.EOF)
		require.ErrorIs(t, err, varsig.ErrBadPrefix)
		assert.Nil(t, vs)
	})

	t.Run("fails - wrong prefix", func(t *testing.T) {
		t.Parallel()

		data, err := hex.DecodeString("42")
		require.NoError(t, err)

		vs, err := varsig.Decode(data)
		require.ErrorIs(t, err, varsig.ErrBadPrefix)
		assert.Nil(t, vs)
	})

	t.Run("fails - unsupported version", func(t *testing.T) {
		t.Parallel()

		data, err := hex.DecodeString("3402")
		require.NoError(t, err)

		vs, err := varsig.Decode(data)
		require.ErrorIs(t, err, varsig.ErrUnsupportedVersion)
		assert.Nil(t, vs)
	})

	t.Run("fails - unknown signature algorithm - v0", func(t *testing.T) {
		t.Parallel()

		data, err := hex.DecodeString("3464")
		require.NoError(t, err)

		vs, err := varsig.Decode(data)
		require.ErrorIs(t, err, varsig.ErrUnknownSignAlgorithm)
		assert.Nil(t, vs)
	})

	t.Run("fails - unknown signature algorithm - v1", func(t *testing.T) {
		t.Parallel()

		data, err := hex.DecodeString("340164")
		require.NoError(t, err)

		vs, err := varsig.Decode(data)
		require.ErrorIs(t, err, varsig.ErrUnknownSignAlgorithm)
		assert.Nil(t, vs)
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

var _ varsig.ParseFunc = testParseFunc(&testing.T{})

func testParseFunc(t *testing.T) varsig.ParseFunc {
	t.Helper()

	return func(r *bytes.Reader, vers varsig.Version, signAlg varsig.SignAlgorithm) (varsig.Varsig, error) {
		return &testVarsig{
			vers:    vers,
			signAlg: signAlg,
		}, nil
	}
}

var _ varsig.Varsig = (*testVarsig)(nil)

type testVarsig struct {
	vers    varsig.Version
	signAlg varsig.SignAlgorithm
}

func (v *testVarsig) Version() varsig.Version {
	return v.vers
}

func (v *testVarsig) SignatureAlgorithm() varsig.SignAlgorithm {
	return v.signAlg
}

func (v *testVarsig) PayloadEncoding() varsig.PayloadEncoding {
	return 0
}

func (v *testVarsig) Signature() []byte {
	return nil
}

func (v *testVarsig) Encode() []byte {
	return nil
}
