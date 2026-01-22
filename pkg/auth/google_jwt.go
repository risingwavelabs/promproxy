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
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const googleJWTRefreshSkew = time.Minute

// GoogleJWTConfig controls the generated JWT for Google upstreams.
type GoogleJWTConfig struct {
	Audience string
	TTL      time.Duration
	Now      func() time.Time
}

type googleServiceAccount struct {
	ClientEmail  string `json:"client_email"`
	PrivateKey   string `json:"private_key"`
	PrivateKeyID string `json:"private_key_id"`
}

// GoogleJWTSource signs self-issued JWTs for Google upstreams.
type GoogleJWTSource struct {
	mu         sync.Mutex
	audience   string
	issuer     string
	keyID      string
	privateKey *rsa.PrivateKey
	now        func() time.Time
	ttl        time.Duration
	token      string
	expiry     time.Time
}

// NewGoogleJWTSourceFromFile loads a service account file and returns a token source.
func NewGoogleJWTSourceFromFile(path string, cfg GoogleJWTConfig) (*GoogleJWTSource, error) {
	if cfg.Audience == "" {
		return nil, errors.New("google jwt audience is required")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read google service account file: %w", err)
	}

	var sa googleServiceAccount
	if err := json.Unmarshal(data, &sa); err != nil {
		return nil, fmt.Errorf("parse google service account file: %w", err)
	}
	if sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, errors.New("google service account file missing client_email or private_key")
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(sa.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("parse google service account private key: %w", err)
	}

	return &GoogleJWTSource{
		audience:   cfg.Audience,
		issuer:     sa.ClientEmail,
		keyID:      sa.PrivateKeyID,
		privateKey: key,
		now:        cfg.Now,
		ttl:        cfg.TTL,
	}, nil
}

// Token returns a cached signed JWT or generates a new one if needed.
func (s *GoogleJWTSource) Token(ctx context.Context) (string, error) {
	_ = ctx

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if s.token != "" && now.Add(googleJWTRefreshSkew).Before(s.expiry) {
		return s.token, nil
	}

	exp := now.Add(s.ttl)
	claims := jwt.MapClaims{
		"iss": s.issuer,
		"sub": s.issuer,
		"aud": s.audience,
		"iat": now.Unix(),
		"exp": exp.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if s.keyID != "" {
		token.Header["kid"] = s.keyID
	}

	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("sign google jwt: %w", err)
	}

	s.token = signed
	s.expiry = exp
	return signed, nil
}
