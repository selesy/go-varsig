package varsig_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/selesy/go-varsig"
)

func TestDecodeEd25519(t *testing.T) {
	t.Parallel()

	t.Run("passes - section 3 example - v0", func(t *testing.T) {
		// Original:  34ed01    1371ae3784f03f9ee1163382fa6efa73b0c31ecf58c899c836709303ba4621d1e6df20e09aaa568914290b7ea124f5b38e70b9b69c7de0d216880eac885edd41c302
		// Corrected: 34ed011371ae3784f03f9ee1163382fa6efa73b0c31ecf58c899c836709303ba4621d1e6df20e09aaa568914290b7ea124f5b38e70b9b69c7de0d216880eac885edd41c302")

		hdr, err := hex.DecodeString("34ed011371")
		require.NoError(t, err)

		sig, err := hex.DecodeString("ae3784f03f9ee1163382fa6efa73b0c31ecf58c899c836709303ba4621d1e6df20e09aaa568914290b7ea124f5b38e70b9b69c7de0d216880eac885edd41c302")
		require.NoError(t, err)
		require.Len(t, sig, 64)

		t.Run("Decode", func(t *testing.T) {
			t.Parallel()

			v, err := varsig.Decode(append(hdr, sig...))
			require.NoError(t, err)
			require.NotNil(t, v)
			assert.Equal(t, varsig.Version0, v.Version())
			assert.Equal(t, varsig.SignAlgorithmEd25519, v.SignatureAlgorithm())
			assert.Equal(t, varsig.PayloadEncodingDAGCBOR, v.PayloadEncoding())
			assert.Len(t, v.Signature(), 64)

			impl, ok := v.(*varsig.EdDSAVarsig)
			require.True(t, ok)
			assert.Equal(t, varsig.CurveEd25519, impl.Curve())
			assert.Equal(t, varsig.HashAlgorithmSHA512, impl.HashAlgorithm())
		})

		t.Run("Encode", func(t *testing.T) {
			t.Parallel()

			v, err := varsig.NewEdDSAVarsig(
				varsig.CurveEd25519,
				varsig.HashAlgorithmSHA512,
				varsig.PayloadEncodingDAGCBOR,
				varsig.WithForceVersion0(sig),
			)
			require.NoError(t, err)
			require.NotNil(t, v)
			assert.Equal(t, append(hdr, sig...), v.Encode())
		})
	})
}
