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
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// SigV4Config controls AWS SigV4 signing behavior.
type SigV4Config struct {
	// Region is the AWS region to sign against (for example, "us-east-1").
	// It must be non-empty; NewSigV4Transport returns an error when empty.
	Region string
	// Service is the AWS service name to sign against (for example, "es" or "s3").
	// It must be non-empty; NewSigV4Transport returns an error when empty.
	Service string
	// Credentials provides AWS credentials used for signing. It must be non-nil.
	Credentials aws.CredentialsProvider
	// Signer is the SigV4 signer implementation. If nil, NewSigV4Transport
	// defaults to v4.NewSigner().
	Signer v4.HTTPSigner
	// Now provides the signing timestamp. If nil, NewSigV4Transport defaults
	// to time.Now. Useful for tests or deterministic signing.
	Now func() time.Time
	// MaxBodyBytes limits how many bytes may be read from req.Body for signing.
	// A value <= 0 or >= math.MaxInt64 means "no limit". If the request body
	// exceeds MaxBodyBytes, RoundTrip returns an error before signing.
	MaxBodyBytes int64
}

type sigV4Transport struct {
	next   http.RoundTripper
	config SigV4Config
}

// NewSigV4Transport returns a RoundTripper that signs requests with AWS SigV4.
func NewSigV4Transport(next http.RoundTripper, cfg SigV4Config) (http.RoundTripper, error) {
	if cfg.Credentials == nil {
		return nil, errors.New("aws credentials provider is required")
	}
	if cfg.Region == "" {
		return nil, errors.New("aws region is required")
	}
	if cfg.Service == "" {
		return nil, errors.New("aws service is required")
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
		credsErr := fmt.Errorf("retrieve aws credentials: %w", err)
		if closeErr := closeRequestBody(req); closeErr != nil {
			return nil, errors.Join(credsErr, closeErr)
		}
		return nil, credsErr
	}

	bodyBytes, err := readRequestBody(req, t.config.MaxBodyBytes)
	if err != nil {
		return nil, err
	}

	reqCopy := req.Clone(req.Context())
	if reqCopy.Header == nil {
		reqCopy.Header = make(http.Header)
	}
	if reqCopy.Body != nil && reqCopy.Body != http.NoBody {
		reqCopy.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		reqCopy.ContentLength = int64(len(bodyBytes))
		reqCopy.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
	} else {
		reqCopy.Body = http.NoBody
		reqCopy.ContentLength = 0
		reqCopy.GetBody = nil
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

func readRequestBody(req *http.Request, maxBytes int64) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}

	bodyBytes, err := readAllWithLimit(req.Body, maxBytes)
	closeErr := req.Body.Close()
	if err != nil {
		if closeErr != nil {
			return nil, errors.Join(err, fmt.Errorf("close request body: %w", closeErr))
		}
		return nil, err
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close request body: %w", closeErr)
	}
	return bodyBytes, nil
}

func readAllWithLimit(reader io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 || maxBytes >= math.MaxInt64 {
		body, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
		return body, nil
	}

	limited := io.LimitReader(reader, maxBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read request body: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("request body exceeds %d bytes", maxBytes)
	}
	return body, nil
}

func closeRequestBody(req *http.Request) error {
	if req.Body != nil && req.Body != http.NoBody {
		if closeErr := req.Body.Close(); closeErr != nil {
			return fmt.Errorf("close request body: %w", closeErr)
		}
	}
	return nil
}

func hashSHA256Hex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
