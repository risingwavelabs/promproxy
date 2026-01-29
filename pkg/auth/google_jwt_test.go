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

	email := "service@example.com"
	path := writeGoogleServiceAccount(t, googleServiceAccount{
		ClientEmail:  email,
		PrivateKey:   string(pemKey),
		PrivateKeyID: "key-123",
	})

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
	require.Equal(t, email, claims["iss"])
	require.Equal(t, email, claims["sub"])
	require.Equal(t, "https://prometheus.example.com", claims["aud"])
	require.Equal(t, float64(fixedTime.Unix()), claims["iat"])
	require.Equal(t, float64(fixedTime.Add(time.Hour).Unix()), claims["exp"])
}

func TestGoogleJWTSourceRefreshesTokens(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	der := x509.MarshalPKCS1PrivateKey(privateKey)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	path := writeGoogleServiceAccount(t, googleServiceAccount{
		ClientEmail: "service@example.com",
		PrivateKey:  string(pemKey),
	})

	fakeNow := time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)
	source, err := NewGoogleJWTSourceFromFile(path, GoogleJWTConfig{
		Audience: "https://prometheus.example.com",
		TTL:      2 * time.Minute,
		Now:      func() time.Time { return fakeNow },
	})
	require.NoError(t, err)

	tokenOne, err := source.Token(context.Background())
	require.NoError(t, err)

	tokenTwo, err := source.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, tokenOne, tokenTwo)

	fakeNow = fakeNow.Add(2 * time.Minute)
	tokenThree, err := source.Token(context.Background())
	require.NoError(t, err)
	require.NotEqual(t, tokenOne, tokenThree)
}

func TestGoogleJWTSourceContextCanceled(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	der := x509.MarshalPKCS1PrivateKey(privateKey)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	path := writeGoogleServiceAccount(t, googleServiceAccount{
		ClientEmail: "service@example.com",
		PrivateKey:  string(pemKey),
	})

	source, err := NewGoogleJWTSourceFromFile(path, GoogleJWTConfig{
		Audience: "https://prometheus.example.com",
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = source.Token(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestGoogleJWTSourceFromFileValidation(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	der := x509.MarshalPKCS1PrivateKey(privateKey)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	tests := []struct {
		name    string
		path    string
		cfg     GoogleJWTConfig
		wantErr string
	}{
		{
			name:    "missing audience",
			path:    "unused.json",
			cfg:     GoogleJWTConfig{},
			wantErr: "google jwt audience is required",
		},
		{
			name:    "missing file",
			path:    filepath.Join(t.TempDir(), "missing.json"),
			cfg:     GoogleJWTConfig{Audience: "audience"},
			wantErr: "read google service account file",
		},
		{
			name:    "malformed json",
			path:    writeRawGoogleServiceAccount(t, []byte("{not-json")),
			cfg:     GoogleJWTConfig{Audience: "audience"},
			wantErr: "parse google service account file",
		},
		{
			name: "missing required fields",
			path: writeGoogleServiceAccount(t, googleServiceAccount{
				ClientEmail: "",
				PrivateKey:  string(pemKey),
			}),
			cfg:     GoogleJWTConfig{Audience: "audience"},
			wantErr: "missing client_email or private_key",
		},
		{
			name: "invalid private key",
			path: writeGoogleServiceAccount(t, googleServiceAccount{
				ClientEmail: "service@example.com",
				PrivateKey:  "not-a-key",
			}),
			cfg:     GoogleJWTConfig{Audience: "audience"},
			wantErr: "parse google service account private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewGoogleJWTSourceFromFile(tt.path, tt.cfg)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func writeGoogleServiceAccount(t *testing.T, sa googleServiceAccount) string {
	t.Helper()

	data, err := json.Marshal(sa)
	require.NoError(t, err)

	return writeRawGoogleServiceAccount(t, data)
}

func writeRawGoogleServiceAccount(t *testing.T, data []byte) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "sa.json")
	require.NoError(t, os.WriteFile(path, data, 0600))
	return path
}
