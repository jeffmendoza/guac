// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
)

// ArtifactUpdate is the builder for updating Artifact entities.
type ArtifactUpdate struct {
	config
	hooks    []Hook
	mutation *ArtifactMutation
}

// Where appends a list predicates to the ArtifactUpdate builder.
func (au *ArtifactUpdate) Where(ps ...predicate.Artifact) *ArtifactUpdate {
	au.mutation.Where(ps...)
	return au
}

// SetAlgorithm sets the "algorithm" field.
func (au *ArtifactUpdate) SetAlgorithm(s string) *ArtifactUpdate {
	au.mutation.SetAlgorithm(s)
	return au
}

// SetDigest sets the "digest" field.
func (au *ArtifactUpdate) SetDigest(s string) *ArtifactUpdate {
	au.mutation.SetDigest(s)
	return au
}

// Mutation returns the ArtifactMutation object of the builder.
func (au *ArtifactUpdate) Mutation() *ArtifactMutation {
	return au.mutation
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (au *ArtifactUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, au.sqlSave, au.mutation, au.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (au *ArtifactUpdate) SaveX(ctx context.Context) int {
	affected, err := au.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (au *ArtifactUpdate) Exec(ctx context.Context) error {
	_, err := au.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (au *ArtifactUpdate) ExecX(ctx context.Context) {
	if err := au.Exec(ctx); err != nil {
		panic(err)
	}
}

func (au *ArtifactUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := sqlgraph.NewUpdateSpec(artifact.Table, artifact.Columns, sqlgraph.NewFieldSpec(artifact.FieldID, field.TypeString))
	if ps := au.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := au.mutation.Algorithm(); ok {
		_spec.SetField(artifact.FieldAlgorithm, field.TypeString, value)
	}
	if value, ok := au.mutation.Digest(); ok {
		_spec.SetField(artifact.FieldDigest, field.TypeString, value)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, au.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{artifact.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	au.mutation.done = true
	return n, nil
}

// ArtifactUpdateOne is the builder for updating a single Artifact entity.
type ArtifactUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *ArtifactMutation
}

// SetAlgorithm sets the "algorithm" field.
func (auo *ArtifactUpdateOne) SetAlgorithm(s string) *ArtifactUpdateOne {
	auo.mutation.SetAlgorithm(s)
	return auo
}

// SetDigest sets the "digest" field.
func (auo *ArtifactUpdateOne) SetDigest(s string) *ArtifactUpdateOne {
	auo.mutation.SetDigest(s)
	return auo
}

// Mutation returns the ArtifactMutation object of the builder.
func (auo *ArtifactUpdateOne) Mutation() *ArtifactMutation {
	return auo.mutation
}

// Where appends a list predicates to the ArtifactUpdate builder.
func (auo *ArtifactUpdateOne) Where(ps ...predicate.Artifact) *ArtifactUpdateOne {
	auo.mutation.Where(ps...)
	return auo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (auo *ArtifactUpdateOne) Select(field string, fields ...string) *ArtifactUpdateOne {
	auo.fields = append([]string{field}, fields...)
	return auo
}

// Save executes the query and returns the updated Artifact entity.
func (auo *ArtifactUpdateOne) Save(ctx context.Context) (*Artifact, error) {
	return withHooks(ctx, auo.sqlSave, auo.mutation, auo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (auo *ArtifactUpdateOne) SaveX(ctx context.Context) *Artifact {
	node, err := auo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (auo *ArtifactUpdateOne) Exec(ctx context.Context) error {
	_, err := auo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (auo *ArtifactUpdateOne) ExecX(ctx context.Context) {
	if err := auo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (auo *ArtifactUpdateOne) sqlSave(ctx context.Context) (_node *Artifact, err error) {
	_spec := sqlgraph.NewUpdateSpec(artifact.Table, artifact.Columns, sqlgraph.NewFieldSpec(artifact.FieldID, field.TypeString))
	id, ok := auo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "Artifact.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := auo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, artifact.FieldID)
		for _, f := range fields {
			if !artifact.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != artifact.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := auo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := auo.mutation.Algorithm(); ok {
		_spec.SetField(artifact.FieldAlgorithm, field.TypeString, value)
	}
	if value, ok := auo.mutation.Digest(); ok {
		_spec.SetField(artifact.FieldDigest, field.TypeString, value)
	}
	_node = &Artifact{config: auo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, auo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{artifact.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	auo.mutation.done = true
	return _node, nil
}
