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
	"sync"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// AzureOAuth2Config controls Azure OAuth2 client credential flow.
type AzureOAuth2Config struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	Scopes       []string
	TokenURL     string
}

type oauthTokenSource struct {
	cfg   clientcredentials.Config
	mu    sync.Mutex
	token *oauth2.Token
}

// NewAzureOAuth2Source creates an OAuth2 client-credential token source.
func NewAzureOAuth2Source(cfg AzureOAuth2Config) (TokenSource, error) {
	if cfg.TenantID == "" {
		return nil, errors.New("azure tenant id is required")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("azure client id is required")
	}
	if cfg.ClientSecret == "" {
		return nil, errors.New("azure client secret is required")
	}
	if len(cfg.Scopes) == 0 {
		return nil, errors.New("azure scopes are required")
	}

	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", cfg.TenantID)
	}

	credCfg := clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     tokenURL,
		Scopes:       cfg.Scopes,
	}

	return &oauthTokenSource{
		cfg: credCfg,
	}, nil
}

func (s *oauthTokenSource) Token(ctx context.Context) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	token := s.token
	if token != nil && token.Valid() {
		return token.AccessToken, nil
	}

	token, err := s.cfg.TokenSource(ctx).Token()
	if err != nil {
		return "", fmt.Errorf("retrieve oauth2 token: %w", err)
	}
	s.token = token
	return token.AccessToken, nil
}
