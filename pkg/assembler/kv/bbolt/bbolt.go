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

package bbolt

import (
	"context"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler/kv"
	jsoniter "github.com/json-iterator/go"
	"go.etcd.io/bbolt"
)

var json = jsoniter.ConfigFastest

type Store struct {
	db *bbolt.DB
}

func GetStore() (kv.Store, error) {
	// TODO add options to take a connection string / db name
	// FIXME need to close database
	db, err := bbolt.Open("./my.db", 0600, nil)
	if err != nil {
		return nil, err
	}
	return &Store{
		db: db,
	}, nil
}

func (s *Store) Get(ctx context.Context, c, k string, v any) error {
	// TODO just creating bucket here, should check if exists and return error
	if err := s.db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(c))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		return nil
	}); err != nil {
		return err
	}
	var val []byte
	if err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(c))
		// fixme copy to outside transaction
		val = b.Get([]byte(k))
		return nil
	}); err != nil {
		return err
	}
	if val == nil {
		return kv.NotFoundError
	}
	return json.Unmarshal(val, v)
}

func (s *Store) Set(ctx context.Context, c, k string, v any) error {
	bts, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := s.db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(c))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		return nil
	}); err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(c))
		return b.Put([]byte(k), bts)
	})
}

func (s *Store) Keys(ctx context.Context, c string) ([]string, error) {
	return nil, nil
}
