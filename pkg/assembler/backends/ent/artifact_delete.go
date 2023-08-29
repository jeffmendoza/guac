// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
)

// ArtifactDelete is the builder for deleting a Artifact entity.
type ArtifactDelete struct {
	config
	hooks    []Hook
	mutation *ArtifactMutation
}

// Where appends a list predicates to the ArtifactDelete builder.
func (ad *ArtifactDelete) Where(ps ...predicate.Artifact) *ArtifactDelete {
	ad.mutation.Where(ps...)
	return ad
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (ad *ArtifactDelete) Exec(ctx context.Context) (int, error) {
	return withHooks(ctx, ad.sqlExec, ad.mutation, ad.hooks)
}

// ExecX is like Exec, but panics if an error occurs.
func (ad *ArtifactDelete) ExecX(ctx context.Context) int {
	n, err := ad.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (ad *ArtifactDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := sqlgraph.NewDeleteSpec(artifact.Table, sqlgraph.NewFieldSpec(artifact.FieldID, field.TypeInt))
	if ps := ad.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, ad.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	ad.mutation.done = true
	return affected, err
}

// ArtifactDeleteOne is the builder for deleting a single Artifact entity.
type ArtifactDeleteOne struct {
	ad *ArtifactDelete
}

// Where appends a list predicates to the ArtifactDelete builder.
func (ado *ArtifactDeleteOne) Where(ps ...predicate.Artifact) *ArtifactDeleteOne {
	ado.ad.mutation.Where(ps...)
	return ado
}

// Exec executes the deletion query.
func (ado *ArtifactDeleteOne) Exec(ctx context.Context) error {
	n, err := ado.ad.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{artifact.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (ado *ArtifactDeleteOne) ExecX(ctx context.Context) {
	if err := ado.Exec(ctx); err != nil {
		panic(err)
	}
}
