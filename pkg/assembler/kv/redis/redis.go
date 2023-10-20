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

package redis

import (
	"context"

	jsoniter "github.com/json-iterator/go"
	"github.com/redis/go-redis/v9"

	"github.com/guacsec/guac/pkg/assembler/kv"
)

var json = jsoniter.ConfigFastest

type Store struct {
	c *redis.Client
}

func GetStore() (kv.Store, error) {
	//opt, err := redis.ParseURL("redis://<user>:<pass>@localhost:6379/<db>")
	//opt, err := redis.ParseURL("redis://user@localhost:6379/0")
	opt, err := redis.ParseURL("redis://user@localhost:2379/0")
	if err != nil {
		return nil, err
	}

	return &Store{
		c: redis.NewClient(opt),
	}, nil
}

func (s *Store) Get(ctx context.Context, c, k string, v any) error {
	j, err := s.c.HGet(ctx, c, k).Result()
	// FIXME, should figure out error
	if j == "" {
		return kv.NotFoundError
	}
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(j), v)
}

func (s *Store) Set(ctx context.Context, c, k string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.c.HSet(ctx, c, k, string(b)).Err()
}

func (s *Store) Keys(ctx context.Context, c string) ([]string, error) {
	return s.c.HKeys(ctx, c).Result()
}
