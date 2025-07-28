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
		require.Equal(t, varsig.HashSha2_256, hashAlg)
	})

	t.Run("fails - truncated varsig (no bytes)", func(t *testing.T) {
		t.Parallel()

		hashAlg, err := varsig.DecodeHashAlgorithm(bytes.NewReader([]byte{}))
		require.ErrorIs(t, err, varsig.ErrUnknownHash)
		require.ErrorIs(t, err, io.EOF)
		require.Equal(t, varsig.HashUnspecified, hashAlg)
	})

	t.Run("fails - unknown hash algorithm", func(t *testing.T) {
		t.Parallel()

		hashAlg, err := varsig.DecodeHashAlgorithm(bytes.NewReader([]byte{0x42}))
		require.ErrorIs(t, err, varsig.ErrUnknownHash)
		require.Equal(t, varsig.HashUnspecified, hashAlg)
	})
}

func BenchmarkDecodeHashAlgorithm(b *testing.B) {
	b.ReportAllocs()
	data := []byte{0x12}
	for i := 0; i < b.N; i++ {
		_, _ = varsig.DecodeHashAlgorithm(bytes.NewReader(data))
	}
}

func TestDecodePayloadEncoding(t *testing.T) {
	t.Parallel()

	t.Run("passes", func(t *testing.T) {
		t.Parallel()

		t.Run("v1", func(t *testing.T) {
			t.Parallel()

			payEnc, err := varsig.DecodePayloadEncoding(bytes.NewReader([]byte{0x5f}))
			require.NoError(t, err)
			require.Equal(t, varsig.PayloadEncodingVerbatim, payEnc)
		})
	})

	t.Run("fails", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name string
			data []byte
			err  error
		}{
			{
				name: "unsupported encoding",
				data: []byte{0x6a, 0x77}, // JWT
				err:  varsig.ErrUnsupportedPayloadEncoding,
			},
		}

		for _, tt := range tests {
			tt := tt
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				r := bytes.NewReader(tt.data)
				_, err := varsig.DecodePayloadEncoding(r)
				require.ErrorIs(t, err, tt.err)
			})
		}
	})
}

func BenchmarkDecodePayloadEncoding(b *testing.B) {
	b.ReportAllocs()
	data := []byte{0x5f}
	for i := 0; i < b.N; i++ {
		_, _ = varsig.DecodePayloadEncoding(bytes.NewReader(data))
	}
}
