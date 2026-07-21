// Copyright Project Harbor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/docker/libtrust"
	"github.com/stretchr/testify/require"
)

// TestGenerateKeyIDMatchesLibtrust guards against a regression where
// generateKeyID's output format diverged from libtrust's key ID algorithm.
// docker distribution registries compute their trusted key IDs from
// rootcertbundle using libtrust's algorithm; if generateKeyID doesn't
// produce the exact same value for the exact same key, every token this
// service issues is silently rejected by an unmodified registry with
// "token signed by untrusted key", even though the underlying key material
// matches.
func TestGenerateKeyIDMatchesLibtrust(t *testing.T) {
	t.Run("RSA", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		got, err := generateKeyID(key)
		require.NoError(t, err)

		want := libtrustKeyID(t, &key.PublicKey)
		require.Equal(t, want, got)
	})

	t.Run("ECDSA", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		got, err := generateKeyID(key)
		require.NoError(t, err)

		want := libtrustKeyID(t, &key.PublicKey)
		require.Equal(t, want, got)
	})
}

// libtrustKeyID computes the expected key ID for pubKey using the real
// libtrust library, as ground truth for what a docker distribution registry
// will compute from the corresponding certificate.
func libtrustKeyID(t *testing.T, pubKey any) string {
	t.Helper()
	ltKey, err := libtrust.FromCryptoPublicKey(pubKey)
	require.NoError(t, err)
	return ltKey.KeyID()
}
