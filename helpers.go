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
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/jeffchao/backoff"
)

// withFieldValidator wraps an OperationFunc and validates the user-supplied
// fields match the schema.
func withFieldValidator(f framework.OperationFunc) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		if err := validateFields(req, d); err != nil {
			return nil, logical.CodedError(400, err.Error())
		}
		return f(ctx, req, d)
	}
}

// validateFields verifies that no bad arguments were given to the request.
func validateFields(req *logical.Request, data *framework.FieldData) error {
	var unknownFields []string
	for k := range req.Data {
		if _, ok := data.Schema[k]; !ok {
			unknownFields = append(unknownFields, k)
		}
	}

	switch len(unknownFields) {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("unknown field: %s", unknownFields[0])
	default:
		sort.Strings(unknownFields)
		return fmt.Errorf("unknown fields: %s", strings.Join(unknownFields, ","))
	}
}

// errMissingFields is a helper to return an error when required fields are
// missing.
func errMissingFields(f ...string) error {
	return logical.CodedError(400, fmt.Sprintf(
		"missing required field(s): %q", f))
}

// retryFib accepts a function and retries using a fibonacci algorithm.
func retryFib(op func() error) error {
	f := backoff.Fibonacci()
	f.Interval = 100 * time.Millisecond
	f.MaxRetries = 5
	return f.Retry(op)
}

// retryExp accepts a function and retries using an exponential backoff
// algorithm.
func retryExp(op func() error) error {
	f := backoff.Exponential()
	f.Interval = 100 * time.Millisecond
	f.MaxRetries = 5
	return f.Retry(op)
}
