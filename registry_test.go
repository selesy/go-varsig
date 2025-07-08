package varsig_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ucan-wg/go-varsig"
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
		assert.Equal(t, testDiscriminator1, vs.Discriminator())
	})

	t.Run("passes - v1", func(t *testing.T) {
		t.Parallel()

		data, err := hex.DecodeString("34018120")
		require.NoError(t, err)

		reg := testRegistry(t)

		vs, err := reg.DecodeStream(bytes.NewReader(data))
		require.NoError(t, err)
		assert.Equal(t, varsig.Version1, vs.Version())
		assert.Equal(t, testDiscriminator1, vs.Discriminator())
	})
}

const (
	testDiscriminator0 varsig.Discriminator = 0x1000
	testDiscriminator1 varsig.Discriminator = 0x1001
)

func testRegistry(t *testing.T) varsig.Registry {
	t.Helper()

	reg := varsig.NewRegistry()
	reg.Register(testDiscriminator0, testDecodeFunc(t))
	reg.Register(testDiscriminator1, testDecodeFunc(t))

	return reg
}

func testDecodeFunc(t *testing.T) varsig.DecodeFunc {
	t.Helper()

	return func(r varsig.BytesReader, vers varsig.Version, disc varsig.Discriminator) (varsig.Varsig, error) {
		v := &testVarsig{
			vers: vers,
			disc: disc,
		}

		return v, nil
	}
}

var _ varsig.Varsig = testVarsig{}

type testVarsig struct {
	vers   varsig.Version
	disc   varsig.Discriminator
	payEnc varsig.PayloadEncoding
	sig    []byte
}

func (v testVarsig) Version() varsig.Version {
	return v.vers
}

func (v testVarsig) Discriminator() varsig.Discriminator {
	return v.disc
}

func (v testVarsig) PayloadEncoding() varsig.PayloadEncoding {
	return v.payEnc
}

func (v testVarsig) Signature() []byte {
	return v.sig
}

func (v testVarsig) Encode() []byte {
	return nil
}
