package varsig_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ucan-wg/go-varsig"
)

func TestDecodeHashAlgorithm(t *testing.T) {
	t.Parallel()

	t.Run("passes", func(t *testing.T) {
		t.Parallel()

		hashAlg, err := varsig.DecodeHashAlgorithm(bytes.NewReader([]byte{0x12}))
		require.NoError(t, err)
		require.Equal(t, varsig.HashAlgorithmSHA256, hashAlg)
	})

	t.Run("fails - truncated varsig (no bytes)", func(t *testing.T) {
		t.Parallel()

		hashAlg, err := varsig.DecodeHashAlgorithm(bytes.NewReader([]byte{}))
		require.ErrorIs(t, err, varsig.ErrUnknownHashAlgorithm)
		require.ErrorIs(t, err, io.EOF)
		require.Equal(t, varsig.HashAlgorithmUnspecified, hashAlg)
	})

	t.Run("fails - unknown hash algorithm", func(t *testing.T) {
		t.Parallel()

		hashAlg, err := varsig.DecodeHashAlgorithm(bytes.NewReader([]byte{0x42}))
		require.ErrorIs(t, err, varsig.ErrUnknownHashAlgorithm)
		require.Equal(t, varsig.HashAlgorithmUnspecified, hashAlg)
	})
}

func TestDecodePayloadEncoding(t *testing.T) {
	t.Parallel()

	t.Run("passes", func(t *testing.T) {
		t.Parallel()

		t.Run("v0", func(t *testing.T) {
			t.Parallel()

			payEnc, err := varsig.DecodePayloadEncoding(bytes.NewReader([]byte{0x5f}), varsig.Version1)
			require.NoError(t, err)
			require.Equal(t, varsig.PayloadEncodingVerbatim, payEnc)
		})

		t.Run("v1", func(t *testing.T) {
			t.Parallel()

			payEnc, err := varsig.DecodePayloadEncoding(bytes.NewReader([]byte{0x5f}), varsig.Version1)
			require.NoError(t, err)
			require.Equal(t, varsig.PayloadEncodingVerbatim, payEnc)
		})
	})

	t.Run("fails", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name string
			data []byte
			vers varsig.Version
			err  error
		}{
			{
				name: "unsupported encoding - v0",
				data: []byte{0x42}, // random
				vers: varsig.Version0,
				err:  varsig.ErrUnsupportedPayloadEncoding,
			},
			{
				name: "unsupported encoding - v1",
				data: []byte{0x6a, 0x77}, // JWT
				vers: varsig.Version1,
				err:  varsig.ErrUnsupportedPayloadEncoding,
			},
			{
				name: "unsupported version",
				data: []byte{0x5f}, // Verbatim
				vers: 99,           // random
				err:  varsig.ErrUnsupportedVersion,
			},
		}

		for _, tt := range tests {
			tt := tt
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				r := bytes.NewReader(tt.data)
				_, err := varsig.DecodePayloadEncoding(r, tt.vers)
				require.ErrorIs(t, err, tt.err)
				// t.Log(err)
				// t.Fail()
			})
		}
	})
}
