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
	"go.etcd.io/bbolt"
)

type Store struct {
	db *bbolt.DB
}

func GetStore() (kv.Store, error) {
	// need to close
	db, err := bbolt.Open("./my.db", 0600, nil)
	if err != nil {
		return nil, err
	}
	return &Store{
		db: db,
	}, nil
}

// check interface compatability
var _ kv.Store = &Store{}

func (s *Store) Get(ctx context.Context, c, k string) (string, error) {
	// just create now, should check instead, or create all at startup
	if err := s.db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(c))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		return nil
	}); err != nil {
		return "", err
	}
	var val []byte
	if err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(c))
		// fixme copy to outside transaction
		val = b.Get([]byte(k))
		return nil
	}); err != nil {
		return "", err
	}
	if val == nil {
		return "", kv.KeyError
	}
	return string(val), nil
}

func (s *Store) Set(ctx context.Context, c, k, v string) error {
	err := s.db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(c))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(c))
		return b.Put([]byte(k), []byte(v))
	})
}

func (s *Store) Keys(ctx context.Context, c string) ([]string, error) {
	return nil, nil
}
