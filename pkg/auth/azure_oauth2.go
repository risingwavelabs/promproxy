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
	"time"

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
	Now          func() time.Time
}

const azureOAuth2RefreshSkew = time.Minute

// AzureOAuth2Source retrieves client-credential tokens for Azure upstreams.
type AzureOAuth2Source struct {
	cfg   clientcredentials.Config
	mu    sync.Mutex
	token *oauth2.Token
	now   func() time.Time
}

// NewAzureOAuth2Source creates an OAuth2 client-credential token source.
func NewAzureOAuth2Source(cfg AzureOAuth2Config) (*AzureOAuth2Source, error) {
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
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	credCfg := clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     tokenURL,
		Scopes:       cfg.Scopes,
	}

	return &AzureOAuth2Source{
		cfg: credCfg,
		now: cfg.Now,
	}, nil
}

// Token returns a cached OAuth2 access token or retrieves a new one if needed.
func (s *AzureOAuth2Source) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return "", err
	}

	token := s.token
	now := s.now()
	if token != nil && token.AccessToken != "" {
		if token.Expiry.IsZero() || now.Before(token.Expiry.Add(-azureOAuth2RefreshSkew)) {
			return token.AccessToken, nil
		}
	}

	token, err := s.cfg.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("retrieve oauth2 token: %w", err)
	}
	s.token = token
	return token.AccessToken, nil
}
