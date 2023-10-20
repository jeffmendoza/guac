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

package memmap

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/guacsec/guac/pkg/assembler/kv"
	"golang.org/x/exp/maps"
)

type Store struct {
	m map[string]map[string]any
}

func GetStore() kv.Store {
	return &Store{
		m: make(map[string]map[string]any),
	}
}

func (s *Store) Get(_ context.Context, c, k string, v any) error {
	col, ok := s.m[c]
	if !ok {
		return fmt.Errorf("%w : %s %s", kv.NotFoundError, c, k)
	}
	val, ok := col[k]
	if !ok {
		return fmt.Errorf("%w : %s %s", kv.NotFoundError, c, k)
	}

	return copyAny(val, v)
}

func (s *Store) Set(_ context.Context, c, k string, v any) error {
	if s.m[c] == nil {
		s.m[c] = make(map[string]any)
	}
	s.m[c][k] = v
	return nil
}

func (s *Store) Keys(_ context.Context, c string) ([]string, error) {
	if s.m[c] == nil {
		return nil, nil
	}
	return maps.Keys(s.m[c]), nil
}

func copyAny(src any, dst any) error {
	dP := reflect.ValueOf(dst)
	if dP.Kind() != reflect.Pointer {
		return errors.New("Destination not pointer")
	}
	d := dP.Elem()
	if !d.CanSet() {
		return errors.New("Destination not settable")
	}
	s := reflect.ValueOf(src)
	// if s.Kind() == reflect.Pointer {
	// 	s = s.Elem()
	// }
	if s.Type() != d.Type() {
		return fmt.Errorf("Source and Destination not same type: %v, %v", s.Type(), d.Type())
	}
	d.Set(s)
	return nil
}
