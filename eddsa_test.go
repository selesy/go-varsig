package varsig_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ucan-wg/go-varsig"
)

func TestUCANExampleV1(t *testing.T) {
	t.Parallel()

	// This test is the value shown in the UCAN v1.0.0 example, which is
	// an EdDSA varsig = v1 with the Ed25519 curve, SHA2_256 hashing and
	// DAG-CBOR content encoding.
	example, err := base64.RawStdEncoding.DecodeString("NAHtAe0BE3E")
	require.NoError(t, err)

	t.Run("Decode", func(t *testing.T) {
		t.Parallel()

		v, err := varsig.Decode(example)
		require.NoError(t, err)

		ed25519V, ok := v.(varsig.EdDSAVarsig)
		require.True(t, ok)

		assert.Equal(t, varsig.Version1, ed25519V.Version())
		assert.Equal(t, varsig.AlgorithmEdDSA, ed25519V.Algorithm())
		assert.Equal(t, varsig.CurveEd25519, ed25519V.Curve())
		assert.Equal(t, varsig.HashSha2_512, ed25519V.Hash())
		assert.Equal(t, varsig.PayloadEncodingDAGCBOR, ed25519V.PayloadEncoding())
	})

	t.Run("Encode", func(t *testing.T) {
		t.Parallel()

		edDSAVarsig := varsig.NewEdDSAVarsig(
			varsig.CurveEd25519,
			varsig.HashSha2_512,
			varsig.PayloadEncodingDAGCBOR,
		)

		assert.Equal(t, example, edDSAVarsig.Encode())
		t.Log(base64.RawStdEncoding.EncodeToString(edDSAVarsig.Encode()))
	})
}
