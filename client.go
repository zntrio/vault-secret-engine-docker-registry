// Licensed to zntrio under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. zntrio licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package dockerregistry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/square/go-jose/v3/jwt"
)

// RegistryClient declares Docker Registry contract.
type RegistryClient interface {
	Token(ctx context.Context, endpoint, clientID, username, password, service, scope string) (*RegistryToken, error)
}

// -----------------------------------------------------------------------------

// RegistryToken represents a registry token information holder.
type RegistryToken struct {
	RegistryURL   string
	Service       string
	RequestScopes []string
	TokenScopes   []string
	Token         string
	AccessToken   string
	ExpiresAt     time.Time
}

// AsMap returns registry token as map.
func (rt *RegistryToken) AsMap() map[string]interface{} {
	return map[string]interface{}{
		"registry_url":   rt.RegistryURL,
		"service":        rt.Service,
		"request_scopes": rt.RequestScopes,
		"token_scopes":   rt.TokenScopes,
		"token":          rt.Token,
		"access_token":   rt.AccessToken,
		"expires_at":     rt.ExpiresAt.UTC(),
	}
}

// -----------------------------------------------------------------------------

type jwtClaims struct {
	Audience  string      `json:"aud"`
	Issuer    string      `json:"iss"`
	ExpiresAt uint64      `json:"exp"`
	NotBefore uint64      `json:"nbf"`
	IssuedAt  uint64      `json:"iat"`
	Access    []jwtAccess `json:"access"`
}

type jwtAccess struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

func (ja *jwtAccess) String() string {
	return fmt.Sprintf("%s:%s:%s", ja.Type, ja.Name, strings.Join(ja.Actions, ","))
}

// -----------------------------------------------------------------------------

// tokenResponse represents docker registry token response.
type tokenResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	IssuedAt    string `json:"issued_at"`
	JTI         string `json:"jti"`
	Subject     string `json:"sub"`
}

// -----------------------------------------------------------------------------

type registryClient struct {
	httpClient *http.Client
}

// NewRegistryClient returns a default docker registry client implementation.
func NewRegistryClient() RegistryClient {
	return &registryClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Token call external authentication endpoint to rtrieve a session token.
func (rc *registryClient) Token(ctx context.Context, endpoint, clientID, username, password, service, scope string) (*RegistryToken, error) {
	// Check arguments
	if endpoint == "" {
		return nil, errors.New("unable to query registry without endpoint url defined")
	}

	// Parse endpoint
	endpointURL, err := url.Parse(fmt.Sprintf("%s/token", endpoint))
	if err != nil {
		return nil, fmt.Errorf("endpoint_url is not a valid URL: %v", err)
	}

	// Prepare context
	rctx, rcancel := context.WithTimeout(ctx, 30*time.Second)
	defer rcancel()

	// Prepare params
	params := url.Values{}

	if clientID != "" {
		params.Add("client_id", clientID)
	}
	if service != "" {
		params.Add("service", service)
	}
	if scope != "" {
		params.Add("scope", scope)
	}
	endpointURL.RawQuery = params.Encode()

	// Prepare request
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, endpointURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("unable to prepare docker registry request: %v", err)
	}

	// Assign basic authentication if credentials provided
	if username != "" && password != "" {
		req.SetBasicAuth(username, password)
	}

	// Do the request
	resp, err := rc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error getting auth token for service='%s' scope='%s': %v", service, scope, err)
	}
	defer resp.Body.Close()

	// Drain body
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("error getting auth token for %q: %s", scope, resp.Status)
	}

	// Extract token response
	var data tokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 5<<20)).Decode(&data); err != nil {
		return nil, fmt.Errorf("error parsing token for %q: %s", scope, resp.Status)
	}

	// Decode JWT to extract effective accesses
	token, err := jwt.ParseSigned(data.Token)
	if err != nil {
		return nil, fmt.Errorf("error validating token for %q: %s", scope, resp.Status)
	}

	// Can't check signature complete certificate chain is not provided

	// Extract scope form token
	var claims jwtClaims
	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, fmt.Errorf("unable to extract token claims: %v", err)
	}

	tokenScopes := []string{}
	for _, s := range claims.Access {
		tokenScopes = append(tokenScopes, s.String())
	}

	// No error
	return &RegistryToken{
		RegistryURL:   endpoint,
		Service:       service,
		RequestScopes: strings.Split(scope, " "),
		TokenScopes:   tokenScopes,
		Token:         data.Token,
		AccessToken:   data.AccessToken,
		ExpiresAt:     time.Now().Add(time.Duration(data.ExpiresIn) * time.Second),
	}, nil
}
