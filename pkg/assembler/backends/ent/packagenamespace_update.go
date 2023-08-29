// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenamespace"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagetype"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
)

// PackageNamespaceUpdate is the builder for updating PackageNamespace entities.
type PackageNamespaceUpdate struct {
	config
	hooks    []Hook
	mutation *PackageNamespaceMutation
}

// Where appends a list predicates to the PackageNamespaceUpdate builder.
func (pnu *PackageNamespaceUpdate) Where(ps ...predicate.PackageNamespace) *PackageNamespaceUpdate {
	pnu.mutation.Where(ps...)
	return pnu
}

// SetPackageID sets the "package_id" field.
func (pnu *PackageNamespaceUpdate) SetPackageID(i int) *PackageNamespaceUpdate {
	pnu.mutation.SetPackageID(i)
	return pnu
}

// SetNamespace sets the "namespace" field.
func (pnu *PackageNamespaceUpdate) SetNamespace(s string) *PackageNamespaceUpdate {
	pnu.mutation.SetNamespace(s)
	return pnu
}

// SetPackage sets the "package" edge to the PackageType entity.
func (pnu *PackageNamespaceUpdate) SetPackage(p *PackageType) *PackageNamespaceUpdate {
	return pnu.SetPackageID(p.ID)
}

// AddNameIDs adds the "names" edge to the PackageName entity by IDs.
func (pnu *PackageNamespaceUpdate) AddNameIDs(ids ...int) *PackageNamespaceUpdate {
	pnu.mutation.AddNameIDs(ids...)
	return pnu
}

// AddNames adds the "names" edges to the PackageName entity.
func (pnu *PackageNamespaceUpdate) AddNames(p ...*PackageName) *PackageNamespaceUpdate {
	ids := make([]int, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return pnu.AddNameIDs(ids...)
}

// Mutation returns the PackageNamespaceMutation object of the builder.
func (pnu *PackageNamespaceUpdate) Mutation() *PackageNamespaceMutation {
	return pnu.mutation
}

// ClearPackage clears the "package" edge to the PackageType entity.
func (pnu *PackageNamespaceUpdate) ClearPackage() *PackageNamespaceUpdate {
	pnu.mutation.ClearPackage()
	return pnu
}

// ClearNames clears all "names" edges to the PackageName entity.
func (pnu *PackageNamespaceUpdate) ClearNames() *PackageNamespaceUpdate {
	pnu.mutation.ClearNames()
	return pnu
}

// RemoveNameIDs removes the "names" edge to PackageName entities by IDs.
func (pnu *PackageNamespaceUpdate) RemoveNameIDs(ids ...int) *PackageNamespaceUpdate {
	pnu.mutation.RemoveNameIDs(ids...)
	return pnu
}

// RemoveNames removes "names" edges to PackageName entities.
func (pnu *PackageNamespaceUpdate) RemoveNames(p ...*PackageName) *PackageNamespaceUpdate {
	ids := make([]int, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return pnu.RemoveNameIDs(ids...)
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (pnu *PackageNamespaceUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, pnu.sqlSave, pnu.mutation, pnu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (pnu *PackageNamespaceUpdate) SaveX(ctx context.Context) int {
	affected, err := pnu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (pnu *PackageNamespaceUpdate) Exec(ctx context.Context) error {
	_, err := pnu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (pnu *PackageNamespaceUpdate) ExecX(ctx context.Context) {
	if err := pnu.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (pnu *PackageNamespaceUpdate) check() error {
	if _, ok := pnu.mutation.PackageID(); pnu.mutation.PackageCleared() && !ok {
		return errors.New(`ent: clearing a required unique edge "PackageNamespace.package"`)
	}
	return nil
}

func (pnu *PackageNamespaceUpdate) sqlSave(ctx context.Context) (n int, err error) {
	if err := pnu.check(); err != nil {
		return n, err
	}
	_spec := sqlgraph.NewUpdateSpec(packagenamespace.Table, packagenamespace.Columns, sqlgraph.NewFieldSpec(packagenamespace.FieldID, field.TypeInt))
	if ps := pnu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := pnu.mutation.Namespace(); ok {
		_spec.SetField(packagenamespace.FieldNamespace, field.TypeString, value)
	}
	if pnu.mutation.PackageCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   packagenamespace.PackageTable,
			Columns: []string{packagenamespace.PackageColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packagetype.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pnu.mutation.PackageIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   packagenamespace.PackageTable,
			Columns: []string{packagenamespace.PackageColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packagetype.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if pnu.mutation.NamesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   packagenamespace.NamesTable,
			Columns: []string{packagenamespace.NamesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packagename.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pnu.mutation.RemovedNamesIDs(); len(nodes) > 0 && !pnu.mutation.NamesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   packagenamespace.NamesTable,
			Columns: []string{packagenamespace.NamesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packagename.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pnu.mutation.NamesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   packagenamespace.NamesTable,
			Columns: []string{packagenamespace.NamesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packagename.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, pnu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{packagenamespace.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	pnu.mutation.done = true
	return n, nil
}

// PackageNamespaceUpdateOne is the builder for updating a single PackageNamespace entity.
type PackageNamespaceUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *PackageNamespaceMutation
}

// SetPackageID sets the "package_id" field.
func (pnuo *PackageNamespaceUpdateOne) SetPackageID(i int) *PackageNamespaceUpdateOne {
	pnuo.mutation.SetPackageID(i)
	return pnuo
}

// SetNamespace sets the "namespace" field.
func (pnuo *PackageNamespaceUpdateOne) SetNamespace(s string) *PackageNamespaceUpdateOne {
	pnuo.mutation.SetNamespace(s)
	return pnuo
}

// SetPackage sets the "package" edge to the PackageType entity.
func (pnuo *PackageNamespaceUpdateOne) SetPackage(p *PackageType) *PackageNamespaceUpdateOne {
	return pnuo.SetPackageID(p.ID)
}

// AddNameIDs adds the "names" edge to the PackageName entity by IDs.
func (pnuo *PackageNamespaceUpdateOne) AddNameIDs(ids ...int) *PackageNamespaceUpdateOne {
	pnuo.mutation.AddNameIDs(ids...)
	return pnuo
}

// AddNames adds the "names" edges to the PackageName entity.
func (pnuo *PackageNamespaceUpdateOne) AddNames(p ...*PackageName) *PackageNamespaceUpdateOne {
	ids := make([]int, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return pnuo.AddNameIDs(ids...)
}

// Mutation returns the PackageNamespaceMutation object of the builder.
func (pnuo *PackageNamespaceUpdateOne) Mutation() *PackageNamespaceMutation {
	return pnuo.mutation
}

// ClearPackage clears the "package" edge to the PackageType entity.
func (pnuo *PackageNamespaceUpdateOne) ClearPackage() *PackageNamespaceUpdateOne {
	pnuo.mutation.ClearPackage()
	return pnuo
}

// ClearNames clears all "names" edges to the PackageName entity.
func (pnuo *PackageNamespaceUpdateOne) ClearNames() *PackageNamespaceUpdateOne {
	pnuo.mutation.ClearNames()
	return pnuo
}

// RemoveNameIDs removes the "names" edge to PackageName entities by IDs.
func (pnuo *PackageNamespaceUpdateOne) RemoveNameIDs(ids ...int) *PackageNamespaceUpdateOne {
	pnuo.mutation.RemoveNameIDs(ids...)
	return pnuo
}

// RemoveNames removes "names" edges to PackageName entities.
func (pnuo *PackageNamespaceUpdateOne) RemoveNames(p ...*PackageName) *PackageNamespaceUpdateOne {
	ids := make([]int, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return pnuo.RemoveNameIDs(ids...)
}

// Where appends a list predicates to the PackageNamespaceUpdate builder.
func (pnuo *PackageNamespaceUpdateOne) Where(ps ...predicate.PackageNamespace) *PackageNamespaceUpdateOne {
	pnuo.mutation.Where(ps...)
	return pnuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (pnuo *PackageNamespaceUpdateOne) Select(field string, fields ...string) *PackageNamespaceUpdateOne {
	pnuo.fields = append([]string{field}, fields...)
	return pnuo
}

// Save executes the query and returns the updated PackageNamespace entity.
func (pnuo *PackageNamespaceUpdateOne) Save(ctx context.Context) (*PackageNamespace, error) {
	return withHooks(ctx, pnuo.sqlSave, pnuo.mutation, pnuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (pnuo *PackageNamespaceUpdateOne) SaveX(ctx context.Context) *PackageNamespace {
	node, err := pnuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (pnuo *PackageNamespaceUpdateOne) Exec(ctx context.Context) error {
	_, err := pnuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (pnuo *PackageNamespaceUpdateOne) ExecX(ctx context.Context) {
	if err := pnuo.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (pnuo *PackageNamespaceUpdateOne) check() error {
	if _, ok := pnuo.mutation.PackageID(); pnuo.mutation.PackageCleared() && !ok {
		return errors.New(`ent: clearing a required unique edge "PackageNamespace.package"`)
	}
	return nil
}

func (pnuo *PackageNamespaceUpdateOne) sqlSave(ctx context.Context) (_node *PackageNamespace, err error) {
	if err := pnuo.check(); err != nil {
		return _node, err
	}
	_spec := sqlgraph.NewUpdateSpec(packagenamespace.Table, packagenamespace.Columns, sqlgraph.NewFieldSpec(packagenamespace.FieldID, field.TypeInt))
	id, ok := pnuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "PackageNamespace.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := pnuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, packagenamespace.FieldID)
		for _, f := range fields {
			if !packagenamespace.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != packagenamespace.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := pnuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := pnuo.mutation.Namespace(); ok {
		_spec.SetField(packagenamespace.FieldNamespace, field.TypeString, value)
	}
	if pnuo.mutation.PackageCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   packagenamespace.PackageTable,
			Columns: []string{packagenamespace.PackageColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packagetype.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pnuo.mutation.PackageIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   packagenamespace.PackageTable,
			Columns: []string{packagenamespace.PackageColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packagetype.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if pnuo.mutation.NamesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   packagenamespace.NamesTable,
			Columns: []string{packagenamespace.NamesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packagename.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pnuo.mutation.RemovedNamesIDs(); len(nodes) > 0 && !pnuo.mutation.NamesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   packagenamespace.NamesTable,
			Columns: []string{packagenamespace.NamesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packagename.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pnuo.mutation.NamesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   packagenamespace.NamesTable,
			Columns: []string{packagenamespace.NamesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packagename.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &PackageNamespace{config: pnuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, pnuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{packagenamespace.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	pnuo.mutation.done = true
	return _node, nil
}
