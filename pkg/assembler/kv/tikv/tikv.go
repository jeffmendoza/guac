//
// Copyright 2023 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tikv

import (
	"context"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/kv"
	"github.com/tikv/client-go/v2/config"
	kvti "github.com/tikv/client-go/v2/kv"
	"github.com/tikv/client-go/v2/rawkv"
)

type Store struct {
	c *rawkv.Client
}

func GetStore(ctx context.Context) (kv.Store, error) {
	c, err := rawkv.NewClient(ctx, []string{"127.0.0.1:2379"}, config.Security{})
	if err != nil {
		return nil, err
	}
	return &Store{
		c: c,
	}, nil
}

func (s *Store) Get(ctx context.Context, c, k string) (string, error) {
	ck := strings.Join([]string{c, k}, ":")
	bts, err := s.c.Get(ctx, []byte(ck))
	return string(bts), err
}

func (s *Store) Set(ctx context.Context, c, k, v string) error {
	ck := strings.Join([]string{c, k}, ":")
	return s.c.Put(ctx, []byte(ck), []byte(v))
}

func (s *Store) Keys(ctx context.Context, c string) ([]string, error) {
	ks, _, err := s.c.Scan(ctx, []byte(c), kvti.PrefixNextKey([]byte(c)), 10000, rawkv.ScanKeyOnly())
	if err != nil {
		return nil, err
	}
	rv := make([]string, len(ks))
	for i, k := range ks {
		rv[i] = string(k)
	}
	return rv, nil
}
