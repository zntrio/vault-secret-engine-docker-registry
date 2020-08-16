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
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
)

const (
	defaultEndpoint = "https://auth.docker.io"
)

// Config is the stored configuration.
type Config struct {
	EndpointURL string `json:"endpoint_url"`
	ClientID    string `json:"client_id"`
	Username    string `json:"username"`
	Password    string `json:"password"`
}

// DefaultConfig returns a config with the default values.
func DefaultConfig() *Config {
	return &Config{
		EndpointURL: defaultEndpoint,
	}
}

// Update updates the configuration from the given field data.
func (c *Config) Update(d *framework.FieldData) (bool, error) {
	if d == nil {
		return false, nil
	}

	changed := false

	if v, ok := d.GetOk("endpoint_url"); ok {
		nv := strings.TrimSpace(v.(string))
		if nv != c.EndpointURL {
			c.EndpointURL = nv
			changed = true
		}
	}

	if v, ok := d.GetOk("client_id"); ok {
		nv := strings.TrimSpace(v.(string))
		if nv != c.ClientID {
			c.ClientID = nv
			changed = true
		}
	}

	if v, ok := d.GetOk("username"); ok {
		nv := strings.TrimSpace(v.(string))
		if nv != c.Username {
			c.Username = nv
			changed = true
		}
	}

	if v, ok := d.GetOk("password"); ok {
		nv := strings.TrimSpace(v.(string))
		if nv != c.Password {
			c.Password = nv
			changed = true
		}
	}

	return changed, nil
}

// AsMap returns configuration object as map.
func (c *Config) AsMap() map[string]interface{} {
	return map[string]interface{}{
		"endpoint_url": c.EndpointURL,
		"client_id":    c.ClientID,
		"username":     c.Username,
		"password":     c.Password,
	}
}
