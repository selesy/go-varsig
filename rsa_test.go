package varsig_test

import (
	"encoding/base64"
	"testing"

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

		require.Equal(t, varsig.Version1, rsaVs.Version())
		require.Equal(t, varsig.DiscriminatorRSA, rsaVs.Discriminator())
		require.Equal(t, varsig.HashSha2_256, rsaVs.Hash())
		require.Equal(t, varsig.PayloadEncodingDAGCBOR, rsaVs.PayloadEncoding())
		require.Equal(t, uint64(keyLen), rsaVs.KeyLength())
	})

	t.Run("Encode", func(t *testing.T) {
		t.Parallel()

		rsaVarsig := varsig.NewRSAVarsig(
			varsig.HashSha2_256,
			keyLen,
			varsig.PayloadEncodingDAGCBOR,
		)

		require.Equal(t, example, rsaVarsig.Encode())
		t.Log(base64.RawStdEncoding.EncodeToString(rsaVarsig.Encode()))
	})
}
