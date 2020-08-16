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

// Role is the stored configuration for role.
type Role struct {
	Name    string   `json:"name"`
	Service string   `json:"service"`
	Scopes  []string `json:"scopes"`
}

// Update updates the role from the given field data.
func (c *Role) Update(d *framework.FieldData) (bool, error) {
	if d == nil {
		return false, nil
	}

	changed := false

	if v, ok := d.GetOk("name"); ok {
		nv := strings.TrimSpace(v.(string))
		if nv != c.Name {
			c.Name = nv
			changed = true
		}
	}

	if v, ok := d.GetOk("service"); ok {
		nv := strings.TrimSpace(v.(string))
		if nv != c.Service {
			c.Service = nv
			changed = true
		}
	}

	if v, ok := d.GetOk("scopes"); ok {
		c.Scopes = v.([]string)
		changed = true
	}

	return changed, nil
}

// AsMap returns role object as map.
func (c *Role) AsMap() map[string]interface{} {
	return map[string]interface{}{
		"name":    c.Name,
		"service": c.Service,
		"scopes":  c.Scopes,
	}
}
