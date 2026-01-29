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
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// TokenSource returns bearer tokens for upstream requests.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

type bearerTransport struct {
	next   http.RoundTripper
	source TokenSource
}

// NewBearerTransport sets the Authorization header to a bearer token for each request,
// overwriting any existing Authorization value.
func NewBearerTransport(next http.RoundTripper, source TokenSource) (http.RoundTripper, error) {
	if next == nil {
		next = http.DefaultTransport
	}
	if source == nil {
		return nil, errors.New("token source is required")
	}
	return &bearerTransport{
		next:   next,
		source: source,
	}, nil
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.source.Token(req.Context())
	if err != nil {
		return nil, fmt.Errorf("get bearer token: %w", err)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("bearer token is empty")
	}

	clone := req.Clone(req.Context())
	if clone.Header == nil {
		clone.Header = make(http.Header)
	}
	clone.Header.Set("Authorization", "Bearer "+token)
	return t.next.RoundTrip(clone)
}
