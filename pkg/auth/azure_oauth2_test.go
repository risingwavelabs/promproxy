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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAzureOAuth2ConfigValidation(t *testing.T) {
	tests := []struct {
		name string
		cfg  AzureOAuth2Config
	}{
		{
			name: "missing tenant",
			cfg: AzureOAuth2Config{
				ClientID:     "client",
				ClientSecret: "secret",
				Scopes:       []string{"https://example.com/.default"},
			},
		},
		{
			name: "missing client id",
			cfg: AzureOAuth2Config{
				TenantID:     "tenant",
				ClientSecret: "secret",
				Scopes:       []string{"https://example.com/.default"},
			},
		},
		{
			name: "missing client secret",
			cfg: AzureOAuth2Config{
				TenantID: "tenant",
				ClientID: "client",
				Scopes:   []string{"https://example.com/.default"},
			},
		},
		{
			name: "missing scopes",
			cfg: AzureOAuth2Config{
				TenantID:     "tenant",
				ClientID:     "client",
				ClientSecret: "secret",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewAzureOAuth2Source(test.cfg)
			require.Error(t, err)
		})
	}
}

func TestAzureOAuth2TokenSourceCachesToken(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"token-%d","token_type":"Bearer","expires_in":3600}`, callCount)
	}))
	defer server.Close()

	fakeNow := time.Now()
	source, err := NewAzureOAuth2Source(AzureOAuth2Config{
		TenantID:     "tenant",
		ClientID:     "client",
		ClientSecret: "secret",
		Scopes:       []string{"https://example.com/.default"},
		TokenURL:     server.URL,
		Now:          func() time.Time { return fakeNow },
	})
	require.NoError(t, err)

	tokenOne, err := source.Token(context.Background())
	require.NoError(t, err)
	tokenTwo, err := source.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, tokenOne, tokenTwo)
	require.Equal(t, 1, callCount)
}

func TestAzureOAuth2TokenSourceRefreshesToken(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"token-%d","token_type":"Bearer","expires_in":1}`, callCount)
	}))
	defer server.Close()

	fakeNow := time.Now()
	source, err := NewAzureOAuth2Source(AzureOAuth2Config{
		TenantID:     "tenant",
		ClientID:     "client",
		ClientSecret: "secret",
		Scopes:       []string{"https://example.com/.default"},
		TokenURL:     server.URL,
		Now:          func() time.Time { return fakeNow },
	})
	require.NoError(t, err)

	tokenOne, err := source.Token(context.Background())
	require.NoError(t, err)
	require.NotNil(t, source.token)
	fakeNow = source.token.Expiry.Add(azureOAuth2RefreshSkew + time.Second)

	tokenTwo, err := source.Token(context.Background())
	require.NoError(t, err)
	require.NotEqual(t, tokenOne, tokenTwo)
	require.Equal(t, 2, callCount)
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

func TestAzureOAuth2TokenSourceCancelsInFlight(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
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
	errCh := make(chan error, 1)
	go func() {
		_, err := source.Token(ctx)
		errCh <- err
	}()

	<-started
	cancel()

	err = <-errCh
	require.Error(t, err)
}
