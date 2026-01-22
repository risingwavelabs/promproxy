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
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBearerTransportAddsAuthorization(t *testing.T) {
	var gotAuth string
	transport := NewBearerTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotAuth = req.Header.Get("Authorization")
		return emptyResponse(), nil
	}), tokenSourceFunc(func(context.Context) (string, error) {
		return "token-123", nil
	}))

	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	require.NoError(t, err)

	_, err = transport.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, "Bearer token-123", gotAuth)
}

func TestBearerTransportPropagatesErrors(t *testing.T) {
	transport := NewBearerTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return emptyResponse(), nil
	}), tokenSourceFunc(func(context.Context) (string, error) {
		return "", errors.New("boom")
	}))

	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	require.NoError(t, err)

	_, err = transport.RoundTrip(req)
	require.Error(t, err)
}
