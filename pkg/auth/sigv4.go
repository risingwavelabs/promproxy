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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// SigV4Config controls AWS SigV4 signing behavior.
type SigV4Config struct {
	Region      string
	Service     string
	Credentials aws.CredentialsProvider
	Signer      v4.HTTPSigner
	Now         func() time.Time
}

type sigV4Transport struct {
	next   http.RoundTripper
	config SigV4Config
}

// NewSigV4Transport returns a RoundTripper that signs requests with AWS SigV4.
func NewSigV4Transport(next http.RoundTripper, cfg SigV4Config) (http.RoundTripper, error) {
	if cfg.Credentials == nil {
		return nil, fmt.Errorf("aws credentials provider is required")
	}
	if cfg.Region == "" {
		return nil, fmt.Errorf("aws region is required")
	}
	if cfg.Service == "" {
		return nil, fmt.Errorf("aws service is required")
	}
	if cfg.Signer == nil {
		cfg.Signer = v4.NewSigner()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if next == nil {
		next = http.DefaultTransport
	}
	return &sigV4Transport{
		next:   next,
		config: cfg,
	}, nil
}

func (t *sigV4Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	creds, err := t.config.Credentials.Retrieve(req.Context())
	if err != nil {
		return nil, fmt.Errorf("retrieve aws credentials: %w", err)
	}

	bodyBytes, err := readRequestBody(req)
	if err != nil {
		return nil, err
	}

	reqCopy := req.Clone(req.Context())
	reqCopy.Header = reqCopy.Header.Clone()
	if reqCopy.Body != nil && reqCopy.Body != http.NoBody {
		reqCopy.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		reqCopy.ContentLength = int64(len(bodyBytes))
	} else {
		reqCopy.Body = http.NoBody
		reqCopy.ContentLength = 0
	}

	payloadHash := hashSHA256Hex(bodyBytes)
	if err := t.config.Signer.SignHTTP(
		req.Context(),
		creds,
		reqCopy,
		payloadHash,
		t.config.Service,
		t.config.Region,
		t.config.Now(),
	); err != nil {
		return nil, fmt.Errorf("sign aws request: %w", err)
	}
	return t.next.RoundTrip(reqCopy)
}

func readRequestBody(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}
	if req.GetBody != nil {
		reader, err := req.GetBody()
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
		defer reader.Close()
		body, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
		if req.Body != nil && req.Body != http.NoBody {
			if closeErr := req.Body.Close(); closeErr != nil {
				return nil, fmt.Errorf("close request body: %w", closeErr)
			}
		}
		return body, nil
	}

	bodyBytes, err := io.ReadAll(req.Body)
	closeErr := req.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("read request body: %w", err)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close request body: %w", closeErr)
	}
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return bodyBytes, nil
}

func hashSHA256Hex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
