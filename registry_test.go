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
	t.Run("passes - v1", func(t *testing.T) {
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
	reg.Register(testDiscriminator0, testDecodeFunc(testDiscriminator0))
	reg.Register(testDiscriminator1, testDecodeFunc(testDiscriminator1))

	return reg
}

func testDecodeFunc(disc varsig.Discriminator) varsig.DecodeFunc {
	return func(r varsig.BytesReader) (varsig.Varsig, error) {
		return &testVarsig{disc: disc}, nil
	}
}

var _ varsig.Varsig = testVarsig{}

type testVarsig struct {
	disc   varsig.Discriminator
	payEnc varsig.PayloadEncoding
}

func (v testVarsig) Version() varsig.Version {
	return varsig.Version1
}

func (v testVarsig) Discriminator() varsig.Discriminator {
	return v.disc
}

func (v testVarsig) PayloadEncoding() varsig.PayloadEncoding {
	return v.payEnc
}

func (v testVarsig) Encode() []byte {
	return nil
}
