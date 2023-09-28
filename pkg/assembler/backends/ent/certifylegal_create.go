// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifylegal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/license"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
)

// CertifyLegalCreate is the builder for creating a CertifyLegal entity.
type CertifyLegalCreate struct {
	config
	mutation *CertifyLegalMutation
	hooks    []Hook
	conflict []sql.ConflictOption
}

// SetPackageID sets the "package_id" field.
func (clc *CertifyLegalCreate) SetPackageID(i int) *CertifyLegalCreate {
	clc.mutation.SetPackageID(i)
	return clc
}

// SetNillablePackageID sets the "package_id" field if the given value is not nil.
func (clc *CertifyLegalCreate) SetNillablePackageID(i *int) *CertifyLegalCreate {
	if i != nil {
		clc.SetPackageID(*i)
	}
	return clc
}

// SetSourceID sets the "source_id" field.
func (clc *CertifyLegalCreate) SetSourceID(i int) *CertifyLegalCreate {
	clc.mutation.SetSourceID(i)
	return clc
}

// SetNillableSourceID sets the "source_id" field if the given value is not nil.
func (clc *CertifyLegalCreate) SetNillableSourceID(i *int) *CertifyLegalCreate {
	if i != nil {
		clc.SetSourceID(*i)
	}
	return clc
}

// SetDeclaredLicense sets the "declared_license" field.
func (clc *CertifyLegalCreate) SetDeclaredLicense(s string) *CertifyLegalCreate {
	clc.mutation.SetDeclaredLicense(s)
	return clc
}

// SetDiscoveredLicense sets the "discovered_license" field.
func (clc *CertifyLegalCreate) SetDiscoveredLicense(s string) *CertifyLegalCreate {
	clc.mutation.SetDiscoveredLicense(s)
	return clc
}

// SetAttribution sets the "attribution" field.
func (clc *CertifyLegalCreate) SetAttribution(s string) *CertifyLegalCreate {
	clc.mutation.SetAttribution(s)
	return clc
}

// SetJustification sets the "justification" field.
func (clc *CertifyLegalCreate) SetJustification(s string) *CertifyLegalCreate {
	clc.mutation.SetJustification(s)
	return clc
}

// SetTimeScanned sets the "time_scanned" field.
func (clc *CertifyLegalCreate) SetTimeScanned(t time.Time) *CertifyLegalCreate {
	clc.mutation.SetTimeScanned(t)
	return clc
}

// SetOrigin sets the "origin" field.
func (clc *CertifyLegalCreate) SetOrigin(s string) *CertifyLegalCreate {
	clc.mutation.SetOrigin(s)
	return clc
}

// SetCollector sets the "collector" field.
func (clc *CertifyLegalCreate) SetCollector(s string) *CertifyLegalCreate {
	clc.mutation.SetCollector(s)
	return clc
}

// SetDeclaredLicensesHash sets the "declared_licenses_hash" field.
func (clc *CertifyLegalCreate) SetDeclaredLicensesHash(s string) *CertifyLegalCreate {
	clc.mutation.SetDeclaredLicensesHash(s)
	return clc
}

// SetDiscoveredLicensesHash sets the "discovered_licenses_hash" field.
func (clc *CertifyLegalCreate) SetDiscoveredLicensesHash(s string) *CertifyLegalCreate {
	clc.mutation.SetDiscoveredLicensesHash(s)
	return clc
}

// SetPackage sets the "package" edge to the PackageVersion entity.
func (clc *CertifyLegalCreate) SetPackage(p *PackageVersion) *CertifyLegalCreate {
	return clc.SetPackageID(p.ID)
}

// SetSource sets the "source" edge to the SourceName entity.
func (clc *CertifyLegalCreate) SetSource(s *SourceName) *CertifyLegalCreate {
	return clc.SetSourceID(s.ID)
}

// AddDeclaredLicenseIDs adds the "declared_licenses" edge to the License entity by IDs.
func (clc *CertifyLegalCreate) AddDeclaredLicenseIDs(ids ...int) *CertifyLegalCreate {
	clc.mutation.AddDeclaredLicenseIDs(ids...)
	return clc
}

// AddDeclaredLicenses adds the "declared_licenses" edges to the License entity.
func (clc *CertifyLegalCreate) AddDeclaredLicenses(l ...*License) *CertifyLegalCreate {
	ids := make([]int, len(l))
	for i := range l {
		ids[i] = l[i].ID
	}
	return clc.AddDeclaredLicenseIDs(ids...)
}

// AddDiscoveredLicenseIDs adds the "discovered_licenses" edge to the License entity by IDs.
func (clc *CertifyLegalCreate) AddDiscoveredLicenseIDs(ids ...int) *CertifyLegalCreate {
	clc.mutation.AddDiscoveredLicenseIDs(ids...)
	return clc
}

// AddDiscoveredLicenses adds the "discovered_licenses" edges to the License entity.
func (clc *CertifyLegalCreate) AddDiscoveredLicenses(l ...*License) *CertifyLegalCreate {
	ids := make([]int, len(l))
	for i := range l {
		ids[i] = l[i].ID
	}
	return clc.AddDiscoveredLicenseIDs(ids...)
}

// Mutation returns the CertifyLegalMutation object of the builder.
func (clc *CertifyLegalCreate) Mutation() *CertifyLegalMutation {
	return clc.mutation
}

// Save creates the CertifyLegal in the database.
func (clc *CertifyLegalCreate) Save(ctx context.Context) (*CertifyLegal, error) {
	return withHooks(ctx, clc.sqlSave, clc.mutation, clc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (clc *CertifyLegalCreate) SaveX(ctx context.Context) *CertifyLegal {
	v, err := clc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (clc *CertifyLegalCreate) Exec(ctx context.Context) error {
	_, err := clc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (clc *CertifyLegalCreate) ExecX(ctx context.Context) {
	if err := clc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (clc *CertifyLegalCreate) check() error {
	if _, ok := clc.mutation.DeclaredLicense(); !ok {
		return &ValidationError{Name: "declared_license", err: errors.New(`ent: missing required field "CertifyLegal.declared_license"`)}
	}
	if _, ok := clc.mutation.DiscoveredLicense(); !ok {
		return &ValidationError{Name: "discovered_license", err: errors.New(`ent: missing required field "CertifyLegal.discovered_license"`)}
	}
	if _, ok := clc.mutation.Attribution(); !ok {
		return &ValidationError{Name: "attribution", err: errors.New(`ent: missing required field "CertifyLegal.attribution"`)}
	}
	if _, ok := clc.mutation.Justification(); !ok {
		return &ValidationError{Name: "justification", err: errors.New(`ent: missing required field "CertifyLegal.justification"`)}
	}
	if _, ok := clc.mutation.TimeScanned(); !ok {
		return &ValidationError{Name: "time_scanned", err: errors.New(`ent: missing required field "CertifyLegal.time_scanned"`)}
	}
	if _, ok := clc.mutation.Origin(); !ok {
		return &ValidationError{Name: "origin", err: errors.New(`ent: missing required field "CertifyLegal.origin"`)}
	}
	if _, ok := clc.mutation.Collector(); !ok {
		return &ValidationError{Name: "collector", err: errors.New(`ent: missing required field "CertifyLegal.collector"`)}
	}
	if _, ok := clc.mutation.DeclaredLicensesHash(); !ok {
		return &ValidationError{Name: "declared_licenses_hash", err: errors.New(`ent: missing required field "CertifyLegal.declared_licenses_hash"`)}
	}
	if _, ok := clc.mutation.DiscoveredLicensesHash(); !ok {
		return &ValidationError{Name: "discovered_licenses_hash", err: errors.New(`ent: missing required field "CertifyLegal.discovered_licenses_hash"`)}
	}
	return nil
}

func (clc *CertifyLegalCreate) sqlSave(ctx context.Context) (*CertifyLegal, error) {
	if err := clc.check(); err != nil {
		return nil, err
	}
	_node, _spec := clc.createSpec()
	if err := sqlgraph.CreateNode(ctx, clc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	clc.mutation.id = &_node.ID
	clc.mutation.done = true
	return _node, nil
}

func (clc *CertifyLegalCreate) createSpec() (*CertifyLegal, *sqlgraph.CreateSpec) {
	var (
		_node = &CertifyLegal{config: clc.config}
		_spec = sqlgraph.NewCreateSpec(certifylegal.Table, sqlgraph.NewFieldSpec(certifylegal.FieldID, field.TypeInt))
	)
	_spec.OnConflict = clc.conflict
	if value, ok := clc.mutation.DeclaredLicense(); ok {
		_spec.SetField(certifylegal.FieldDeclaredLicense, field.TypeString, value)
		_node.DeclaredLicense = value
	}
	if value, ok := clc.mutation.DiscoveredLicense(); ok {
		_spec.SetField(certifylegal.FieldDiscoveredLicense, field.TypeString, value)
		_node.DiscoveredLicense = value
	}
	if value, ok := clc.mutation.Attribution(); ok {
		_spec.SetField(certifylegal.FieldAttribution, field.TypeString, value)
		_node.Attribution = value
	}
	if value, ok := clc.mutation.Justification(); ok {
		_spec.SetField(certifylegal.FieldJustification, field.TypeString, value)
		_node.Justification = value
	}
	if value, ok := clc.mutation.TimeScanned(); ok {
		_spec.SetField(certifylegal.FieldTimeScanned, field.TypeTime, value)
		_node.TimeScanned = value
	}
	if value, ok := clc.mutation.Origin(); ok {
		_spec.SetField(certifylegal.FieldOrigin, field.TypeString, value)
		_node.Origin = value
	}
	if value, ok := clc.mutation.Collector(); ok {
		_spec.SetField(certifylegal.FieldCollector, field.TypeString, value)
		_node.Collector = value
	}
	if value, ok := clc.mutation.DeclaredLicensesHash(); ok {
		_spec.SetField(certifylegal.FieldDeclaredLicensesHash, field.TypeString, value)
		_node.DeclaredLicensesHash = value
	}
	if value, ok := clc.mutation.DiscoveredLicensesHash(); ok {
		_spec.SetField(certifylegal.FieldDiscoveredLicensesHash, field.TypeString, value)
		_node.DiscoveredLicensesHash = value
	}
	if nodes := clc.mutation.PackageIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   certifylegal.PackageTable,
			Columns: []string{certifylegal.PackageColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packageversion.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.PackageID = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := clc.mutation.SourceIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   certifylegal.SourceTable,
			Columns: []string{certifylegal.SourceColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(sourcename.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.SourceID = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := clc.mutation.DeclaredLicensesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: false,
			Table:   certifylegal.DeclaredLicensesTable,
			Columns: certifylegal.DeclaredLicensesPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(license.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := clc.mutation.DiscoveredLicensesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: false,
			Table:   certifylegal.DiscoveredLicensesTable,
			Columns: certifylegal.DiscoveredLicensesPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(license.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.CertifyLegal.Create().
//		SetPackageID(v).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.CertifyLegalUpsert) {
//			SetPackageID(v+v).
//		}).
//		Exec(ctx)
func (clc *CertifyLegalCreate) OnConflict(opts ...sql.ConflictOption) *CertifyLegalUpsertOne {
	clc.conflict = opts
	return &CertifyLegalUpsertOne{
		create: clc,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.CertifyLegal.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (clc *CertifyLegalCreate) OnConflictColumns(columns ...string) *CertifyLegalUpsertOne {
	clc.conflict = append(clc.conflict, sql.ConflictColumns(columns...))
	return &CertifyLegalUpsertOne{
		create: clc,
	}
}

type (
	// CertifyLegalUpsertOne is the builder for "upsert"-ing
	//  one CertifyLegal node.
	CertifyLegalUpsertOne struct {
		create *CertifyLegalCreate
	}

	// CertifyLegalUpsert is the "OnConflict" setter.
	CertifyLegalUpsert struct {
		*sql.UpdateSet
	}
)

// SetPackageID sets the "package_id" field.
func (u *CertifyLegalUpsert) SetPackageID(v int) *CertifyLegalUpsert {
	u.Set(certifylegal.FieldPackageID, v)
	return u
}

// UpdatePackageID sets the "package_id" field to the value that was provided on create.
func (u *CertifyLegalUpsert) UpdatePackageID() *CertifyLegalUpsert {
	u.SetExcluded(certifylegal.FieldPackageID)
	return u
}

// ClearPackageID clears the value of the "package_id" field.
func (u *CertifyLegalUpsert) ClearPackageID() *CertifyLegalUpsert {
	u.SetNull(certifylegal.FieldPackageID)
	return u
}

// SetSourceID sets the "source_id" field.
func (u *CertifyLegalUpsert) SetSourceID(v int) *CertifyLegalUpsert {
	u.Set(certifylegal.FieldSourceID, v)
	return u
}

// UpdateSourceID sets the "source_id" field to the value that was provided on create.
func (u *CertifyLegalUpsert) UpdateSourceID() *CertifyLegalUpsert {
	u.SetExcluded(certifylegal.FieldSourceID)
	return u
}

// ClearSourceID clears the value of the "source_id" field.
func (u *CertifyLegalUpsert) ClearSourceID() *CertifyLegalUpsert {
	u.SetNull(certifylegal.FieldSourceID)
	return u
}

// SetDeclaredLicense sets the "declared_license" field.
func (u *CertifyLegalUpsert) SetDeclaredLicense(v string) *CertifyLegalUpsert {
	u.Set(certifylegal.FieldDeclaredLicense, v)
	return u
}

// UpdateDeclaredLicense sets the "declared_license" field to the value that was provided on create.
func (u *CertifyLegalUpsert) UpdateDeclaredLicense() *CertifyLegalUpsert {
	u.SetExcluded(certifylegal.FieldDeclaredLicense)
	return u
}

// SetDiscoveredLicense sets the "discovered_license" field.
func (u *CertifyLegalUpsert) SetDiscoveredLicense(v string) *CertifyLegalUpsert {
	u.Set(certifylegal.FieldDiscoveredLicense, v)
	return u
}

// UpdateDiscoveredLicense sets the "discovered_license" field to the value that was provided on create.
func (u *CertifyLegalUpsert) UpdateDiscoveredLicense() *CertifyLegalUpsert {
	u.SetExcluded(certifylegal.FieldDiscoveredLicense)
	return u
}

// SetAttribution sets the "attribution" field.
func (u *CertifyLegalUpsert) SetAttribution(v string) *CertifyLegalUpsert {
	u.Set(certifylegal.FieldAttribution, v)
	return u
}

// UpdateAttribution sets the "attribution" field to the value that was provided on create.
func (u *CertifyLegalUpsert) UpdateAttribution() *CertifyLegalUpsert {
	u.SetExcluded(certifylegal.FieldAttribution)
	return u
}

// SetJustification sets the "justification" field.
func (u *CertifyLegalUpsert) SetJustification(v string) *CertifyLegalUpsert {
	u.Set(certifylegal.FieldJustification, v)
	return u
}

// UpdateJustification sets the "justification" field to the value that was provided on create.
func (u *CertifyLegalUpsert) UpdateJustification() *CertifyLegalUpsert {
	u.SetExcluded(certifylegal.FieldJustification)
	return u
}

// SetTimeScanned sets the "time_scanned" field.
func (u *CertifyLegalUpsert) SetTimeScanned(v time.Time) *CertifyLegalUpsert {
	u.Set(certifylegal.FieldTimeScanned, v)
	return u
}

// UpdateTimeScanned sets the "time_scanned" field to the value that was provided on create.
func (u *CertifyLegalUpsert) UpdateTimeScanned() *CertifyLegalUpsert {
	u.SetExcluded(certifylegal.FieldTimeScanned)
	return u
}

// SetOrigin sets the "origin" field.
func (u *CertifyLegalUpsert) SetOrigin(v string) *CertifyLegalUpsert {
	u.Set(certifylegal.FieldOrigin, v)
	return u
}

// UpdateOrigin sets the "origin" field to the value that was provided on create.
func (u *CertifyLegalUpsert) UpdateOrigin() *CertifyLegalUpsert {
	u.SetExcluded(certifylegal.FieldOrigin)
	return u
}

// SetCollector sets the "collector" field.
func (u *CertifyLegalUpsert) SetCollector(v string) *CertifyLegalUpsert {
	u.Set(certifylegal.FieldCollector, v)
	return u
}

// UpdateCollector sets the "collector" field to the value that was provided on create.
func (u *CertifyLegalUpsert) UpdateCollector() *CertifyLegalUpsert {
	u.SetExcluded(certifylegal.FieldCollector)
	return u
}

// SetDeclaredLicensesHash sets the "declared_licenses_hash" field.
func (u *CertifyLegalUpsert) SetDeclaredLicensesHash(v string) *CertifyLegalUpsert {
	u.Set(certifylegal.FieldDeclaredLicensesHash, v)
	return u
}

// UpdateDeclaredLicensesHash sets the "declared_licenses_hash" field to the value that was provided on create.
func (u *CertifyLegalUpsert) UpdateDeclaredLicensesHash() *CertifyLegalUpsert {
	u.SetExcluded(certifylegal.FieldDeclaredLicensesHash)
	return u
}

// SetDiscoveredLicensesHash sets the "discovered_licenses_hash" field.
func (u *CertifyLegalUpsert) SetDiscoveredLicensesHash(v string) *CertifyLegalUpsert {
	u.Set(certifylegal.FieldDiscoveredLicensesHash, v)
	return u
}

// UpdateDiscoveredLicensesHash sets the "discovered_licenses_hash" field to the value that was provided on create.
func (u *CertifyLegalUpsert) UpdateDiscoveredLicensesHash() *CertifyLegalUpsert {
	u.SetExcluded(certifylegal.FieldDiscoveredLicensesHash)
	return u
}

// UpdateNewValues updates the mutable fields using the new values that were set on create.
// Using this option is equivalent to using:
//
//	client.CertifyLegal.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//		).
//		Exec(ctx)
func (u *CertifyLegalUpsertOne) UpdateNewValues() *CertifyLegalUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.CertifyLegal.Create().
//	    OnConflict(sql.ResolveWithIgnore()).
//	    Exec(ctx)
func (u *CertifyLegalUpsertOne) Ignore() *CertifyLegalUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *CertifyLegalUpsertOne) DoNothing() *CertifyLegalUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the CertifyLegalCreate.OnConflict
// documentation for more info.
func (u *CertifyLegalUpsertOne) Update(set func(*CertifyLegalUpsert)) *CertifyLegalUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&CertifyLegalUpsert{UpdateSet: update})
	}))
	return u
}

// SetPackageID sets the "package_id" field.
func (u *CertifyLegalUpsertOne) SetPackageID(v int) *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.SetPackageID(v)
	})
}

// UpdatePackageID sets the "package_id" field to the value that was provided on create.
func (u *CertifyLegalUpsertOne) UpdatePackageID() *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.UpdatePackageID()
	})
}

// ClearPackageID clears the value of the "package_id" field.
func (u *CertifyLegalUpsertOne) ClearPackageID() *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.ClearPackageID()
	})
}

// SetSourceID sets the "source_id" field.
func (u *CertifyLegalUpsertOne) SetSourceID(v int) *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.SetSourceID(v)
	})
}

// UpdateSourceID sets the "source_id" field to the value that was provided on create.
func (u *CertifyLegalUpsertOne) UpdateSourceID() *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.UpdateSourceID()
	})
}

// ClearSourceID clears the value of the "source_id" field.
func (u *CertifyLegalUpsertOne) ClearSourceID() *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.ClearSourceID()
	})
}

// SetDeclaredLicense sets the "declared_license" field.
func (u *CertifyLegalUpsertOne) SetDeclaredLicense(v string) *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.SetDeclaredLicense(v)
	})
}

// UpdateDeclaredLicense sets the "declared_license" field to the value that was provided on create.
func (u *CertifyLegalUpsertOne) UpdateDeclaredLicense() *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.UpdateDeclaredLicense()
	})
}

// SetDiscoveredLicense sets the "discovered_license" field.
func (u *CertifyLegalUpsertOne) SetDiscoveredLicense(v string) *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.SetDiscoveredLicense(v)
	})
}

// UpdateDiscoveredLicense sets the "discovered_license" field to the value that was provided on create.
func (u *CertifyLegalUpsertOne) UpdateDiscoveredLicense() *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.UpdateDiscoveredLicense()
	})
}

// SetAttribution sets the "attribution" field.
func (u *CertifyLegalUpsertOne) SetAttribution(v string) *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.SetAttribution(v)
	})
}

// UpdateAttribution sets the "attribution" field to the value that was provided on create.
func (u *CertifyLegalUpsertOne) UpdateAttribution() *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.UpdateAttribution()
	})
}

// SetJustification sets the "justification" field.
func (u *CertifyLegalUpsertOne) SetJustification(v string) *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.SetJustification(v)
	})
}

// UpdateJustification sets the "justification" field to the value that was provided on create.
func (u *CertifyLegalUpsertOne) UpdateJustification() *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.UpdateJustification()
	})
}

// SetTimeScanned sets the "time_scanned" field.
func (u *CertifyLegalUpsertOne) SetTimeScanned(v time.Time) *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.SetTimeScanned(v)
	})
}

// UpdateTimeScanned sets the "time_scanned" field to the value that was provided on create.
func (u *CertifyLegalUpsertOne) UpdateTimeScanned() *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.UpdateTimeScanned()
	})
}

// SetOrigin sets the "origin" field.
func (u *CertifyLegalUpsertOne) SetOrigin(v string) *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.SetOrigin(v)
	})
}

// UpdateOrigin sets the "origin" field to the value that was provided on create.
func (u *CertifyLegalUpsertOne) UpdateOrigin() *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.UpdateOrigin()
	})
}

// SetCollector sets the "collector" field.
func (u *CertifyLegalUpsertOne) SetCollector(v string) *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.SetCollector(v)
	})
}

// UpdateCollector sets the "collector" field to the value that was provided on create.
func (u *CertifyLegalUpsertOne) UpdateCollector() *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.UpdateCollector()
	})
}

// SetDeclaredLicensesHash sets the "declared_licenses_hash" field.
func (u *CertifyLegalUpsertOne) SetDeclaredLicensesHash(v string) *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.SetDeclaredLicensesHash(v)
	})
}

// UpdateDeclaredLicensesHash sets the "declared_licenses_hash" field to the value that was provided on create.
func (u *CertifyLegalUpsertOne) UpdateDeclaredLicensesHash() *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.UpdateDeclaredLicensesHash()
	})
}

// SetDiscoveredLicensesHash sets the "discovered_licenses_hash" field.
func (u *CertifyLegalUpsertOne) SetDiscoveredLicensesHash(v string) *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.SetDiscoveredLicensesHash(v)
	})
}

// UpdateDiscoveredLicensesHash sets the "discovered_licenses_hash" field to the value that was provided on create.
func (u *CertifyLegalUpsertOne) UpdateDiscoveredLicensesHash() *CertifyLegalUpsertOne {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.UpdateDiscoveredLicensesHash()
	})
}

// Exec executes the query.
func (u *CertifyLegalUpsertOne) Exec(ctx context.Context) error {
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for CertifyLegalCreate.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *CertifyLegalUpsertOne) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}

// Exec executes the UPSERT query and returns the inserted/updated ID.
func (u *CertifyLegalUpsertOne) ID(ctx context.Context) (id int, err error) {
	node, err := u.create.Save(ctx)
	if err != nil {
		return id, err
	}
	return node.ID, nil
}

// IDX is like ID, but panics if an error occurs.
func (u *CertifyLegalUpsertOne) IDX(ctx context.Context) int {
	id, err := u.ID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// CertifyLegalCreateBulk is the builder for creating many CertifyLegal entities in bulk.
type CertifyLegalCreateBulk struct {
	config
	err      error
	builders []*CertifyLegalCreate
	conflict []sql.ConflictOption
}

// Save creates the CertifyLegal entities in the database.
func (clcb *CertifyLegalCreateBulk) Save(ctx context.Context) ([]*CertifyLegal, error) {
	if clcb.err != nil {
		return nil, clcb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(clcb.builders))
	nodes := make([]*CertifyLegal, len(clcb.builders))
	mutators := make([]Mutator, len(clcb.builders))
	for i := range clcb.builders {
		func(i int, root context.Context) {
			builder := clcb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*CertifyLegalMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, clcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					spec.OnConflict = clcb.conflict
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, clcb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				if specs[i].ID.Value != nil {
					id := specs[i].ID.Value.(int64)
					nodes[i].ID = int(id)
				}
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, clcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (clcb *CertifyLegalCreateBulk) SaveX(ctx context.Context) []*CertifyLegal {
	v, err := clcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (clcb *CertifyLegalCreateBulk) Exec(ctx context.Context) error {
	_, err := clcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (clcb *CertifyLegalCreateBulk) ExecX(ctx context.Context) {
	if err := clcb.Exec(ctx); err != nil {
		panic(err)
	}
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.CertifyLegal.CreateBulk(builders...).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.CertifyLegalUpsert) {
//			SetPackageID(v+v).
//		}).
//		Exec(ctx)
func (clcb *CertifyLegalCreateBulk) OnConflict(opts ...sql.ConflictOption) *CertifyLegalUpsertBulk {
	clcb.conflict = opts
	return &CertifyLegalUpsertBulk{
		create: clcb,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.CertifyLegal.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (clcb *CertifyLegalCreateBulk) OnConflictColumns(columns ...string) *CertifyLegalUpsertBulk {
	clcb.conflict = append(clcb.conflict, sql.ConflictColumns(columns...))
	return &CertifyLegalUpsertBulk{
		create: clcb,
	}
}

// CertifyLegalUpsertBulk is the builder for "upsert"-ing
// a bulk of CertifyLegal nodes.
type CertifyLegalUpsertBulk struct {
	create *CertifyLegalCreateBulk
}

// UpdateNewValues updates the mutable fields using the new values that
// were set on create. Using this option is equivalent to using:
//
//	client.CertifyLegal.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//		).
//		Exec(ctx)
func (u *CertifyLegalUpsertBulk) UpdateNewValues() *CertifyLegalUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.CertifyLegal.Create().
//		OnConflict(sql.ResolveWithIgnore()).
//		Exec(ctx)
func (u *CertifyLegalUpsertBulk) Ignore() *CertifyLegalUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *CertifyLegalUpsertBulk) DoNothing() *CertifyLegalUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the CertifyLegalCreateBulk.OnConflict
// documentation for more info.
func (u *CertifyLegalUpsertBulk) Update(set func(*CertifyLegalUpsert)) *CertifyLegalUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&CertifyLegalUpsert{UpdateSet: update})
	}))
	return u
}

// SetPackageID sets the "package_id" field.
func (u *CertifyLegalUpsertBulk) SetPackageID(v int) *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.SetPackageID(v)
	})
}

// UpdatePackageID sets the "package_id" field to the value that was provided on create.
func (u *CertifyLegalUpsertBulk) UpdatePackageID() *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.UpdatePackageID()
	})
}

// ClearPackageID clears the value of the "package_id" field.
func (u *CertifyLegalUpsertBulk) ClearPackageID() *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.ClearPackageID()
	})
}

// SetSourceID sets the "source_id" field.
func (u *CertifyLegalUpsertBulk) SetSourceID(v int) *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.SetSourceID(v)
	})
}

// UpdateSourceID sets the "source_id" field to the value that was provided on create.
func (u *CertifyLegalUpsertBulk) UpdateSourceID() *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.UpdateSourceID()
	})
}

// ClearSourceID clears the value of the "source_id" field.
func (u *CertifyLegalUpsertBulk) ClearSourceID() *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.ClearSourceID()
	})
}

// SetDeclaredLicense sets the "declared_license" field.
func (u *CertifyLegalUpsertBulk) SetDeclaredLicense(v string) *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.SetDeclaredLicense(v)
	})
}

// UpdateDeclaredLicense sets the "declared_license" field to the value that was provided on create.
func (u *CertifyLegalUpsertBulk) UpdateDeclaredLicense() *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.UpdateDeclaredLicense()
	})
}

// SetDiscoveredLicense sets the "discovered_license" field.
func (u *CertifyLegalUpsertBulk) SetDiscoveredLicense(v string) *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.SetDiscoveredLicense(v)
	})
}

// UpdateDiscoveredLicense sets the "discovered_license" field to the value that was provided on create.
func (u *CertifyLegalUpsertBulk) UpdateDiscoveredLicense() *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.UpdateDiscoveredLicense()
	})
}

// SetAttribution sets the "attribution" field.
func (u *CertifyLegalUpsertBulk) SetAttribution(v string) *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.SetAttribution(v)
	})
}

// UpdateAttribution sets the "attribution" field to the value that was provided on create.
func (u *CertifyLegalUpsertBulk) UpdateAttribution() *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.UpdateAttribution()
	})
}

// SetJustification sets the "justification" field.
func (u *CertifyLegalUpsertBulk) SetJustification(v string) *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.SetJustification(v)
	})
}

// UpdateJustification sets the "justification" field to the value that was provided on create.
func (u *CertifyLegalUpsertBulk) UpdateJustification() *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.UpdateJustification()
	})
}

// SetTimeScanned sets the "time_scanned" field.
func (u *CertifyLegalUpsertBulk) SetTimeScanned(v time.Time) *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.SetTimeScanned(v)
	})
}

// UpdateTimeScanned sets the "time_scanned" field to the value that was provided on create.
func (u *CertifyLegalUpsertBulk) UpdateTimeScanned() *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.UpdateTimeScanned()
	})
}

// SetOrigin sets the "origin" field.
func (u *CertifyLegalUpsertBulk) SetOrigin(v string) *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.SetOrigin(v)
	})
}

// UpdateOrigin sets the "origin" field to the value that was provided on create.
func (u *CertifyLegalUpsertBulk) UpdateOrigin() *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.UpdateOrigin()
	})
}

// SetCollector sets the "collector" field.
func (u *CertifyLegalUpsertBulk) SetCollector(v string) *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.SetCollector(v)
	})
}

// UpdateCollector sets the "collector" field to the value that was provided on create.
func (u *CertifyLegalUpsertBulk) UpdateCollector() *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.UpdateCollector()
	})
}

// SetDeclaredLicensesHash sets the "declared_licenses_hash" field.
func (u *CertifyLegalUpsertBulk) SetDeclaredLicensesHash(v string) *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.SetDeclaredLicensesHash(v)
	})
}

// UpdateDeclaredLicensesHash sets the "declared_licenses_hash" field to the value that was provided on create.
func (u *CertifyLegalUpsertBulk) UpdateDeclaredLicensesHash() *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.UpdateDeclaredLicensesHash()
	})
}

// SetDiscoveredLicensesHash sets the "discovered_licenses_hash" field.
func (u *CertifyLegalUpsertBulk) SetDiscoveredLicensesHash(v string) *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.SetDiscoveredLicensesHash(v)
	})
}

// UpdateDiscoveredLicensesHash sets the "discovered_licenses_hash" field to the value that was provided on create.
func (u *CertifyLegalUpsertBulk) UpdateDiscoveredLicensesHash() *CertifyLegalUpsertBulk {
	return u.Update(func(s *CertifyLegalUpsert) {
		s.UpdateDiscoveredLicensesHash()
	})
}

// Exec executes the query.
func (u *CertifyLegalUpsertBulk) Exec(ctx context.Context) error {
	if u.create.err != nil {
		return u.create.err
	}
	for i, b := range u.create.builders {
		if len(b.conflict) != 0 {
			return fmt.Errorf("ent: OnConflict was set for builder %d. Set it on the CertifyLegalCreateBulk instead", i)
		}
	}
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for CertifyLegalCreateBulk.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *CertifyLegalUpsertBulk) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}