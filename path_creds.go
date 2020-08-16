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
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	credsPath = "creds"
)

func (b *backend) pathCreds() []*framework.Path {
	return []*framework.Path{
		{
			Pattern:         credsPath + "/" + framework.GenericNameRegex("name"),
			HelpSynopsis:    `Retrieve a role's creds by role name.`,
			HelpDescription: `Read creds using a role's name to view the login, current password, and last password.`,

			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role",
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: withFieldValidator(b.credReadOperation),
			},
		},
	}
}

// -----------------------------------------------------------------------------

func (b *backend) credReadOperation(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	// Engine configuration
	engine, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Current role name
	roleName := fieldData.Get("name").(string)
	role, err := b.Role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	// Get token (and retry)
	var t *RegistryToken
	if retryFib(func() error {
		var err error
		// Use client to retrieve an access token
		t, err = b.client.Token(ctx, engine.EndpointURL, engine.ClientID, engine.Username, engine.Password, role.Service, strings.Join(role.Scopes, " "))
		return err
	}); err != nil {
		return nil, errwrap.Wrapf("unable to retrieve token: {{err}}", err)
	}

	// No error
	return &logical.Response{
		Data: t.AsMap(),
	}, nil
}
