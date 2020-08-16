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

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	rolesPath = "roles"
)

// -----------------------------------------------------------------------------

func (b *backend) pathListRoles() []*framework.Path {
	return []*framework.Path{
		{
			Pattern:         rolesPath + "/?$",
			HelpSynopsis:    `List existing docker-registry secret engine roles.`,
			HelpDescription: `This path lets you list existing roles that can be used to generate short-lived credentials.`,

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathRoleListOperation,
			},
		},
	}
}

func (b *backend) pathRoles() []*framework.Path {
	return []*framework.Path{
		{
			Pattern:         rolesPath + "/" + framework.GenericNameRegex("name"),
			HelpSynopsis:    `Manage docker-registry token roles.`,
			HelpDescription: `This path lets you manage docker-registry secret engine roles.`,

			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Role name",
				},
				"service": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the service",
					Default:     "registry.docker.io",
				},
				"scopes": {
					Type:        framework.TypeStringSlice,
					Description: "Request scopes",
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: withFieldValidator(b.pathRoleWriteOperation),
				logical.ReadOperation:   withFieldValidator(b.pathRoleReadOperation),
				logical.UpdateOperation: withFieldValidator(b.pathRoleWriteOperation),
				logical.DeleteOperation: withFieldValidator(b.pathRoleDeleteOperation),
			},
		},
	}
}

// -----------------------------------------------------------------------------

func (b *backend) Role(ctx context.Context, s logical.Storage, roleName string) (*Role, error) {
	r := &Role{}

	entry, err := s.Get(ctx, rolesPath+"/"+roleName)
	if err != nil {
		return nil, errwrap.Wrapf("failed to get role from storage: {{err}}", err)
	}
	if entry == nil || len(entry.Value) == 0 {
		return r, nil
	}

	if err := entry.DecodeJSON(&r); err != nil {
		return nil, errwrap.Wrapf("failed to decode configuration: {{err}}", err)
	}
	return r, nil
}

// -----------------------------------------------------------------------------

// pathRoleList retruns the list of exiting roles for docker-registry secret engine.
func (b *backend) pathRoleListOperation(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, rolesPath+"/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathRoleReadOperation(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	roleName := fieldData.Get("name").(string)

	// Retrieve the role from storage.
	role, err := b.Role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: role.AsMap(),
	}, nil
}

func (b *backend) pathRoleWriteOperation(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	roleName := fieldData.Get("name").(string)

	// Get the role, if it exists
	r, err := b.Role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	// Update the configuration
	changed, err := r.Update(fieldData)
	if err != nil {
		return nil, logical.CodedError(400, err.Error())
	}

	// Only do the following if the role is different
	if changed {
		// Generate a new storage entry
		entry, err := logical.StorageEntryJSON(rolesPath+"/"+roleName, r)
		if err != nil {
			return nil, errwrap.Wrapf("failed to generate JSON role: {{err}}", err)
		}

		// Save the storage entry
		if err := req.Storage.Put(ctx, entry); err != nil {
			return nil, errwrap.Wrapf("failed to persist role to storage: {{err}}", err)
		}
	}

	// No error
	return nil, nil
}

func (b *backend) pathRoleDeleteOperation(ctx context.Context, req *logical.Request, fieldData *framework.FieldData) (*logical.Response, error) {
	roleName := fieldData.Get("name").(string)

	if err := req.Storage.Delete(ctx, rolesPath+"/"+roleName); err != nil {
		return nil, err
	}

	// No error
	return nil, nil
}
