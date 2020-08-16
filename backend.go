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
	"sync"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Factory build and initialize the docker-registry secret engine logical backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	registryClient := NewRegistryClient()
	b := newBackend(registryClient)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

// -----------------------------------------------------------------------------

type backend struct {
	*framework.Backend
	sync.RWMutex

	client RegistryClient

	// ctx and ctxCancel are used to control overall plugin shutdown. These
	// contexts are given to any client libraries or requests that should be
	// terminated during plugin termination.
	ctx       context.Context
	ctxCancel context.CancelFunc
	ctxLock   sync.Mutex
}

func newBackend(client RegistryClient) *backend {
	var b backend

	b.ctx, b.ctxCancel = context.WithCancel(context.Background())

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        strings.TrimSpace(backendHelp),

		PathsSpecial: &logical.Paths{
			LocalStorage: []string{
				framework.WALPrefix,
			},
			SealWrapStorage: []string{
				"config",
				"roles/*",
			},
		},
		Paths: framework.PathAppend(
			b.pathConfig(),
			b.pathListRoles(),
			b.pathRoles(),
			b.pathCreds(),
		),

		Clean: b.clean,
	}
	b.client = client

	return &b
}

// clean cancels the shared contexts. This is called just before unmounting
// the plugin.
func (b *backend) clean(_ context.Context) {
	b.ctxLock.Lock()
	b.ctxCancel()
	b.ctxLock.Unlock()
}

// -----------------------------------------------------------------------------

// Config parses and returns the configuration data from the storage backend.
// Even when no user-defined data exists in storage, a Config is returned with
// the default values.
func (b *backend) Config(ctx context.Context, s logical.Storage) (*Config, error) {
	c := DefaultConfig()

	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, errwrap.Wrapf("failed to get configuration from storage: {{err}}", err)
	}
	if entry == nil || len(entry.Value) == 0 {
		return c, nil
	}

	if err := entry.DecodeJSON(&c); err != nil {
		return nil, errwrap.Wrapf("failed to decode configuration: {{err}}", err)
	}
	return c, nil
}

// -----------------------------------------------------------------------------

const backendHelp = `
The docker-registry secret engine is used to generate short-lived docker-registry tokens.
`
