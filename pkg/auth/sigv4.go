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
	// A value of 0 uses the default limit (defaultMaxBodyBytes). Negative values
	// or >= math.MaxInt64 mean "no limit". If the request body exceeds MaxBodyBytes,
	// RoundTrip returns an error before signing.
	MaxBodyBytes int64
}

type sigV4Transport struct {
	next   http.RoundTripper
	config SigV4Config
}

const defaultMaxBodyBytes int64 = 32 << 20

type bodyMode int

const (
	bodyModeNone bodyMode = iota
	bodyModeBuffered
	bodyModeGetBody
)

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
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = defaultMaxBodyBytes
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

	payloadHash, bodyBytes, mode, err := payloadHashAndBody(req, t.config.MaxBodyBytes)
	if err != nil {
		return nil, err
	}

	reqCopy := req.Clone(req.Context())
	if reqCopy.Header == nil {
		reqCopy.Header = make(http.Header)
	}
	switch mode {
	case bodyModeNone:
		reqCopy.Body = http.NoBody
		reqCopy.ContentLength = 0
		reqCopy.GetBody = nil
	case bodyModeBuffered:
		reqCopy.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		reqCopy.ContentLength = int64(len(bodyBytes))
		reqCopy.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
	case bodyModeGetBody:
		body, err := req.GetBody()
		if err != nil {
			return nil, fmt.Errorf("get request body: %w", err)
		}
		reqCopy.Body = body
		reqCopy.GetBody = req.GetBody
	}

	if err := t.config.Signer.SignHTTP(
		req.Context(),
		creds,
		reqCopy,
		payloadHash,
		t.config.Service,
		t.config.Region,
		t.config.Now(),
	); err != nil {
		signErr := fmt.Errorf("sign aws request: %w", err)
		if closeErr := closeRequestBody(reqCopy); closeErr != nil {
			return nil, errors.Join(signErr, closeErr)
		}
		return nil, signErr
	}
	return t.next.RoundTrip(reqCopy)
}

func payloadHashAndBody(req *http.Request, maxBytes int64) (string, []byte, bodyMode, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return hashSHA256Hex(nil), nil, bodyModeNone, nil
	}

	if req.GetBody != nil {
		payloadHash, err := hashRequestBodyFromGetBody(req.GetBody, maxBytes)
		closeErr := closeRequestBody(req)
		if err != nil {
			if closeErr != nil {
				return "", nil, bodyModeNone, errors.Join(err, closeErr)
			}
			return "", nil, bodyModeNone, err
		}
		if closeErr != nil {
			return "", nil, bodyModeNone, closeErr
		}
		return payloadHash, nil, bodyModeGetBody, nil
	}

	bodyBytes, err := readRequestBody(req, maxBytes)
	if err != nil {
		return "", nil, bodyModeNone, err
	}
	return hashSHA256Hex(bodyBytes), bodyBytes, bodyModeBuffered, nil
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

func hashRequestBodyFromGetBody(getBody func() (io.ReadCloser, error), maxBytes int64) (string, error) {
	reader, err := getBody()
	if err != nil {
		return "", fmt.Errorf("get request body: %w", err)
	}

	payloadHash, readErr := hashReaderWithLimit(reader, maxBytes)
	closeErr := reader.Close()
	if readErr != nil {
		if closeErr != nil {
			return "", errors.Join(readErr, fmt.Errorf("close get body reader: %w", closeErr))
		}
		return "", readErr
	}
	if closeErr != nil {
		return "", fmt.Errorf("close get body reader: %w", closeErr)
	}
	return payloadHash, nil
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

func hashReaderWithLimit(reader io.Reader, maxBytes int64) (string, error) {
	hasher := sha256.New()
	if maxBytes <= 0 || maxBytes >= math.MaxInt64 {
		if _, err := io.Copy(hasher, reader); err != nil {
			return "", fmt.Errorf("read request body: %w", err)
		}
		return hex.EncodeToString(hasher.Sum(nil)), nil
	}

	limited := io.LimitReader(reader, maxBytes+1)
	written, err := io.Copy(hasher, limited)
	if err != nil {
		return "", fmt.Errorf("read request body: %w", err)
	}
	if written > maxBytes {
		return "", fmt.Errorf("request body exceeds %d bytes", maxBytes)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
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
