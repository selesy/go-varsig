package varsig_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ucan-wg/go-varsig"
)

func TestRSAVarsig(t *testing.T) {
	t.Parallel()

	const keyLen = 0x100

	// This test uses the same RSA configuration as below but for varsig
	// >= v1
	example, err := base64.RawStdEncoding.DecodeString("NAGFJBKAAnE")
	require.NoError(t, err)

	t.Run("Decode", func(t *testing.T) {
		t.Parallel()

		vs, err := varsig.Decode(example)
		require.NoError(t, err)

		rsaVs, ok := vs.(varsig.RSAVarsig)
		require.True(t, ok)

		assert.Equal(t, varsig.Version1, rsaVs.Version())
		assert.Equal(t, varsig.DiscriminatorRSA, rsaVs.Discriminator())
		assert.Equal(t, varsig.HashAlgorithmSHA256, rsaVs.HashAlgorithm())
		assert.Equal(t, varsig.PayloadEncodingDAGCBOR, rsaVs.PayloadEncoding())
		assert.Equal(t, uint64(keyLen), rsaVs.KeyLength())
		assert.Len(t, rsaVs.Signature(), 0)
	})

	t.Run("Encode", func(t *testing.T) {
		t.Parallel()

		rsaVarsig, err := varsig.NewRSAVarsig(
			varsig.HashAlgorithmSHA256,
			keyLen,
			varsig.PayloadEncodingDAGCBOR,
		)
		require.NoError(t, err)

		assert.Equal(t, example, rsaVarsig.Encode())
		t.Log(base64.RawStdEncoding.EncodeToString(rsaVarsig.Encode()))
	})
}

func TestUCANExample(t *testing.T) {
	t.Parallel()

	const keyLen = 0x100

	// This test is the value shown in the UCAN v1.0.0 example, which is
	// an RSA varsig < v1 encoded as RS256 with a key length of 0x100
	// bytes and DAG-CBOR payload encoding.
	example, err := base64.RawStdEncoding.DecodeString("NIUkEoACcQ")
	require.NoError(t, err)

	t.Run("Decode", func(t *testing.T) {
		t.Parallel()

		vs, err := varsig.Decode(example)
		require.ErrorIs(t, err, varsig.ErrMissingSignature)

		rsaVs, ok := vs.(varsig.RSAVarsig)
		require.True(t, ok)

		assert.Equal(t, varsig.Version0, rsaVs.Version())
		assert.Equal(t, varsig.DiscriminatorRSA, rsaVs.Discriminator())
		assert.Equal(t, varsig.HashAlgorithmSHA256, rsaVs.HashAlgorithm())
		assert.Equal(t, varsig.PayloadEncodingDAGCBOR, rsaVs.PayloadEncoding())
		assert.Equal(t, uint64(keyLen), rsaVs.KeyLength())
		assert.Len(t, rsaVs.Signature(), 0)
	})

	t.Run("Encode", func(t *testing.T) {
		t.Parallel()

		rsaVarsig, err := varsig.NewRSAVarsig(
			varsig.HashAlgorithmSHA256,
			keyLen,
			varsig.PayloadEncodingDAGCBOR,
			varsig.WithForceVersion0([]byte{}),
		)
		require.ErrorIs(t, err, varsig.ErrMissingSignature)

		assert.Equal(t, example, rsaVarsig.Encode())
	})
}
