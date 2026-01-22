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
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/stretchr/testify/require"
)

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
		body, _ := io.ReadAll(req.Body)
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
