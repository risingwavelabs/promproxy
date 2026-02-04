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
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/stretchr/testify/require"
)

type errCredentialsProvider struct {
	err error
}

func (p errCredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	return aws.Credentials{}, p.err
}

type errSigner struct {
	err error
}

func (s errSigner) SignHTTP(
	ctx context.Context,
	credentials aws.Credentials,
	r *http.Request,
	payloadHash string,
	service string,
	region string,
	signingTime time.Time,
	optFns ...func(*v4.SignerOptions),
) error {
	return s.err
}

type errReadCloser struct {
	err error
}

func (r errReadCloser) Read(p []byte) (int, error) {
	return 0, r.err
}

func (r errReadCloser) Close() error {
	return nil
}

type trackingReadCloser struct {
	readCalled  bool
	closeCalled bool
}

func (r *trackingReadCloser) Read(p []byte) (int, error) {
	r.readCalled = true
	return 0, errors.New("unexpected read")
}

func (r *trackingReadCloser) Close() error {
	r.closeCalled = true
	return nil
}

type trackingBody struct {
	reader *strings.Reader
	closed bool
}

func (r *trackingBody) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *trackingBody) Close() error {
	r.closed = true
	return nil
}

func TestSigV4TransportConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     SigV4Config
		wantErr string
	}{
		{
			name: "missing credentials",
			cfg: SigV4Config{
				Region:  "us-east-1",
				Service: "aps",
			},
			wantErr: "aws credentials provider is required",
		},
		{
			name: "missing region",
			cfg: SigV4Config{
				Service:     "aps",
				Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("AKID", "SECRET", "")),
			},
			wantErr: "aws region is required",
		},
		{
			name: "missing service",
			cfg: SigV4Config{
				Region:      "us-east-1",
				Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("AKID", "SECRET", "")),
			},
			wantErr: "aws service is required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewSigV4Transport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return emptyResponse(), nil
			}), test.cfg)
			require.Error(t, err)
			require.Contains(t, err.Error(), test.wantErr)
		})
	}
}

func TestSigV4TransportSignsRequests(t *testing.T) {
	fixedTime := time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)

	var gotAuth string
	var gotDate string
	var gotToken string
	var gotBody string

	transport, err := NewSigV4Transport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotAuth = req.Header.Get("Authorization")
		gotDate = req.Header.Get("X-Amz-Date")
		gotToken = req.Header.Get("X-Amz-Security-Token")
		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		if req.Body != nil && req.Body != http.NoBody {
			require.NoError(t, req.Body.Close())
		}
		gotBody = string(body)
		return emptyResponse(), nil
	}), SigV4Config{
		Region:      "us-east-1",
		Service:     "aps",
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("AKID", "SECRET", "SESSION")),
		Now:         func() time.Time { return fixedTime },
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, "https://aps.example.com/api/v1/query", strings.NewReader("query=up"))
	require.NoError(t, err)

	_, err = transport.RoundTrip(req)
	require.NoError(t, err)
	require.Contains(t, gotAuth, "AWS4-HMAC-SHA256")
	require.Contains(t, gotAuth, "Credential=AKID/20250102/us-east-1/aps/aws4_request")
	require.Equal(t, "20250102T030405Z", gotDate)
	require.Equal(t, "SESSION", gotToken)
	require.Equal(t, "query=up", gotBody)
}

func TestSigV4TransportHandlesNilHeader(t *testing.T) {
	fixedTime := time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)

	var gotAuth string
	transport, err := NewSigV4Transport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotAuth = req.Header.Get("Authorization")
		return emptyResponse(), nil
	}), SigV4Config{
		Region:      "us-east-1",
		Service:     "aps",
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("AKID", "SECRET", "")),
		Now:         func() time.Time { return fixedTime },
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, "https://aps.example.com/api/v1/query", nil)
	require.NoError(t, err)
	req.Header = nil

	_, err = transport.RoundTrip(req)
	require.NoError(t, err)
	require.Contains(t, gotAuth, "AWS4-HMAC-SHA256")
}

func TestSigV4TransportRejectsLargeBody(t *testing.T) {
	transport, err := NewSigV4Transport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return emptyResponse(), nil
	}), SigV4Config{
		Region:       "us-east-1",
		Service:      "aps",
		Credentials:  aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("AKID", "SECRET", "")),
		MaxBodyBytes: 4,
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, "https://aps.example.com/api/v1/query", strings.NewReader("12345"))
	require.NoError(t, err)

	_, err = transport.RoundTrip(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "request body exceeds")
}

func TestSigV4TransportUsesGetBodyWhenAvailable(t *testing.T) {
	fixedTime := time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)

	var gotBody string
	transport, err := NewSigV4Transport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		if req.Body != nil && req.Body != http.NoBody {
			require.NoError(t, req.Body.Close())
		}
		gotBody = string(body)
		return emptyResponse(), nil
	}), SigV4Config{
		Region:      "us-east-1",
		Service:     "aps",
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("AKID", "SECRET", "")),
		Now:         func() time.Time { return fixedTime },
	})
	require.NoError(t, err)

	trackedBody := &trackingReadCloser{}
	req, err := http.NewRequest(
		http.MethodPost,
		"https://aps.example.com/api/v1/query",
		trackedBody,
	)
	require.NoError(t, err)
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("query=up")), nil
	}
	req.ContentLength = int64(len("query=up"))

	_, err = transport.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, "query=up", gotBody)
	require.False(t, trackedBody.readCalled)
	require.True(t, trackedBody.closeCalled)
}

func TestSigV4TransportSignerErrorClosesGetBody(t *testing.T) {
	fixedTime := time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)

	var bodies []*trackingBody
	getBody := func() (io.ReadCloser, error) {
		body := &trackingBody{reader: strings.NewReader("query=up")}
		bodies = append(bodies, body)
		return body, nil
	}

	transport, err := NewSigV4Transport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return emptyResponse(), nil
	}), SigV4Config{
		Region:      "us-east-1",
		Service:     "aps",
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("AKID", "SECRET", "")),
		Now:         func() time.Time { return fixedTime },
		Signer:      errSigner{err: errors.New("sign failed")},
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, "https://aps.example.com/api/v1/query", strings.NewReader("query=up"))
	require.NoError(t, err)
	req.GetBody = getBody

	_, err = transport.RoundTrip(req)
	require.Error(t, err)
	require.Len(t, bodies, 2)
	require.True(t, bodies[0].closed)
	require.True(t, bodies[1].closed)
}

func TestSigV4TransportCredentialsError(t *testing.T) {
	transport, err := NewSigV4Transport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return emptyResponse(), nil
	}), SigV4Config{
		Region:      "us-east-1",
		Service:     "aps",
		Credentials: errCredentialsProvider{err: errors.New("no credentials")},
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, "https://aps.example.com/api/v1/query", nil)
	require.NoError(t, err)

	_, err = transport.RoundTrip(req)
	require.Error(t, err)
}

func TestSigV4TransportBodyReadError(t *testing.T) {
	transport, err := NewSigV4Transport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return emptyResponse(), nil
	}), SigV4Config{
		Region:      "us-east-1",
		Service:     "aps",
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("AKID", "SECRET", "")),
	})
	require.NoError(t, err)

	req, err := http.NewRequest(
		http.MethodPost,
		"https://aps.example.com/api/v1/query",
		errReadCloser{err: errors.New("read failed")},
	)
	require.NoError(t, err)

	_, err = transport.RoundTrip(req)
	require.Error(t, err)
}

func TestSigV4TransportSignerError(t *testing.T) {
	transport, err := NewSigV4Transport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return emptyResponse(), nil
	}), SigV4Config{
		Region:      "us-east-1",
		Service:     "aps",
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("AKID", "SECRET", "")),
		Signer:      errSigner{err: errors.New("sign failed")},
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, "https://aps.example.com/api/v1/query", nil)
	require.NoError(t, err)

	_, err = transport.RoundTrip(req)
	require.Error(t, err)
}
