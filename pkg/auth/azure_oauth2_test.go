// Copyright 2025 RisingWave Labs.
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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAzureOAuth2ConfigValidation(t *testing.T) {
	_, err := NewAzureOAuth2Source(AzureOAuth2Config{})
	require.Error(t, err)
}

func TestAzureOAuth2TokenSourceCachesToken(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"token-%d","token_type":"Bearer","expires_in":3600}`, callCount)
	}))
	defer server.Close()

	source, err := NewAzureOAuth2Source(AzureOAuth2Config{
		TenantID:     "tenant",
		ClientID:     "client",
		ClientSecret: "secret",
		Scopes:       []string{"https://example.com/.default"},
		TokenURL:     server.URL,
	})
	require.NoError(t, err)

	tokenOne, err := source.Token(context.Background())
	require.NoError(t, err)
	tokenTwo, err := source.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, tokenOne, tokenTwo)
	require.Equal(t, 1, callCount)
}

func TestAzureOAuth2TokenSourceReturnsTokenErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()

	source, err := NewAzureOAuth2Source(AzureOAuth2Config{
		TenantID:     "tenant",
		ClientID:     "client",
		ClientSecret: "secret",
		Scopes:       []string{"https://example.com/.default"},
		TokenURL:     server.URL,
	})
	require.NoError(t, err)

	_, err = source.Token(context.Background())
	require.Error(t, err)
}

func TestAzureOAuth2TokenSourceHonorsContext(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"token","token_type":"Bearer","expires_in":3600}`)
	}))
	defer server.Close()

	source, err := NewAzureOAuth2Source(AzureOAuth2Config{
		TenantID:     "tenant",
		ClientID:     "client",
		ClientSecret: "secret",
		Scopes:       []string{"https://example.com/.default"},
		TokenURL:     server.URL,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = source.Token(ctx)
	require.Error(t, err)
	require.Equal(t, 0, callCount)
}
