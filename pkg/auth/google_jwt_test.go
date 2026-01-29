// Copyright 2026 RisingWave Labs.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestGoogleJWTSourceSignsTokens(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	der := x509.MarshalPKCS1PrivateKey(privateKey)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	serviceAccount := googleServiceAccount{
		ClientEmail:  "service@example.com",
		PrivateKey:   string(pemKey),
		PrivateKeyID: "key-123",
	}
	data, err := json.Marshal(serviceAccount)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "sa.json")
	require.NoError(t, os.WriteFile(path, data, 0600))

	fixedTime := time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)
	source, err := NewGoogleJWTSourceFromFile(path, GoogleJWTConfig{
		Audience: "https://prometheus.example.com",
		TTL:      time.Hour,
		Now:      func() time.Time { return fixedTime },
	})
	require.NoError(t, err)

	tokenString, err := source.Token(context.Background())
	require.NoError(t, err)

	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithTimeFunc(func() time.Time { return fixedTime }),
	)
	parsed, err := parser.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	require.Equal(t, "key-123", parsed.Header["kid"])
	require.Equal(t, serviceAccount.ClientEmail, claims["iss"])
	require.Equal(t, serviceAccount.ClientEmail, claims["sub"])
	require.Equal(t, "https://prometheus.example.com", claims["aud"])
	require.Equal(t, float64(fixedTime.Unix()), claims["iat"])
	require.Equal(t, float64(fixedTime.Add(time.Hour).Unix()), claims["exp"])
}

func TestGoogleJWTSourceRefreshesTokens(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	der := x509.MarshalPKCS1PrivateKey(privateKey)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	serviceAccount := googleServiceAccount{
		ClientEmail: "service@example.com",
		PrivateKey:  string(pemKey),
	}
	data, err := json.Marshal(serviceAccount)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "sa.json")
	require.NoError(t, os.WriteFile(path, data, 0600))

	now := time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)
	source, err := NewGoogleJWTSourceFromFile(path, GoogleJWTConfig{
		Audience: "https://prometheus.example.com",
		TTL:      2 * time.Minute,
		Now:      func() time.Time { return now },
	})
	require.NoError(t, err)

	tokenOne, err := source.Token(context.Background())
	require.NoError(t, err)

	tokenTwo, err := source.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, tokenOne, tokenTwo)

	now = now.Add(2 * time.Minute)
	tokenThree, err := source.Token(context.Background())
	require.NoError(t, err)
	require.NotEqual(t, tokenOne, tokenThree)
}
