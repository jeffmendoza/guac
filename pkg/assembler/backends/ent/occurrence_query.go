// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/occurrence"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
)

// OccurrenceQuery is the builder for querying Occurrence entities.
type OccurrenceQuery struct {
	config
	ctx          *QueryContext
	order        []occurrence.OrderOption
	inters       []Interceptor
	predicates   []predicate.Occurrence
	withArtifact *ArtifactQuery
	withPackage  *PackageVersionQuery
	withSource   *SourceNameQuery
	modifiers    []func(*sql.Selector)
	loadTotal    []func(context.Context, []*Occurrence) error
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the OccurrenceQuery builder.
func (oq *OccurrenceQuery) Where(ps ...predicate.Occurrence) *OccurrenceQuery {
	oq.predicates = append(oq.predicates, ps...)
	return oq
}

// Limit the number of records to be returned by this query.
func (oq *OccurrenceQuery) Limit(limit int) *OccurrenceQuery {
	oq.ctx.Limit = &limit
	return oq
}

// Offset to start from.
func (oq *OccurrenceQuery) Offset(offset int) *OccurrenceQuery {
	oq.ctx.Offset = &offset
	return oq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (oq *OccurrenceQuery) Unique(unique bool) *OccurrenceQuery {
	oq.ctx.Unique = &unique
	return oq
}

// Order specifies how the records should be ordered.
func (oq *OccurrenceQuery) Order(o ...occurrence.OrderOption) *OccurrenceQuery {
	oq.order = append(oq.order, o...)
	return oq
}

// QueryArtifact chains the current query on the "artifact" edge.
func (oq *OccurrenceQuery) QueryArtifact() *ArtifactQuery {
	query := (&ArtifactClient{config: oq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := oq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := oq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(occurrence.Table, occurrence.FieldID, selector),
			sqlgraph.To(artifact.Table, artifact.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, occurrence.ArtifactTable, occurrence.ArtifactColumn),
		)
		fromU = sqlgraph.SetNeighbors(oq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryPackage chains the current query on the "package" edge.
func (oq *OccurrenceQuery) QueryPackage() *PackageVersionQuery {
	query := (&PackageVersionClient{config: oq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := oq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := oq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(occurrence.Table, occurrence.FieldID, selector),
			sqlgraph.To(packageversion.Table, packageversion.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, occurrence.PackageTable, occurrence.PackageColumn),
		)
		fromU = sqlgraph.SetNeighbors(oq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QuerySource chains the current query on the "source" edge.
func (oq *OccurrenceQuery) QuerySource() *SourceNameQuery {
	query := (&SourceNameClient{config: oq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := oq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := oq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(occurrence.Table, occurrence.FieldID, selector),
			sqlgraph.To(sourcename.Table, sourcename.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, occurrence.SourceTable, occurrence.SourceColumn),
		)
		fromU = sqlgraph.SetNeighbors(oq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first Occurrence entity from the query.
// Returns a *NotFoundError when no Occurrence was found.
func (oq *OccurrenceQuery) First(ctx context.Context) (*Occurrence, error) {
	nodes, err := oq.Limit(1).All(setContextOp(ctx, oq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{occurrence.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (oq *OccurrenceQuery) FirstX(ctx context.Context) *Occurrence {
	node, err := oq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first Occurrence ID from the query.
// Returns a *NotFoundError when no Occurrence ID was found.
func (oq *OccurrenceQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = oq.Limit(1).IDs(setContextOp(ctx, oq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{occurrence.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (oq *OccurrenceQuery) FirstIDX(ctx context.Context) int {
	id, err := oq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single Occurrence entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one Occurrence entity is found.
// Returns a *NotFoundError when no Occurrence entities are found.
func (oq *OccurrenceQuery) Only(ctx context.Context) (*Occurrence, error) {
	nodes, err := oq.Limit(2).All(setContextOp(ctx, oq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{occurrence.Label}
	default:
		return nil, &NotSingularError{occurrence.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (oq *OccurrenceQuery) OnlyX(ctx context.Context) *Occurrence {
	node, err := oq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only Occurrence ID in the query.
// Returns a *NotSingularError when more than one Occurrence ID is found.
// Returns a *NotFoundError when no entities are found.
func (oq *OccurrenceQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = oq.Limit(2).IDs(setContextOp(ctx, oq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{occurrence.Label}
	default:
		err = &NotSingularError{occurrence.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (oq *OccurrenceQuery) OnlyIDX(ctx context.Context) int {
	id, err := oq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of Occurrences.
func (oq *OccurrenceQuery) All(ctx context.Context) ([]*Occurrence, error) {
	ctx = setContextOp(ctx, oq.ctx, "All")
	if err := oq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*Occurrence, *OccurrenceQuery]()
	return withInterceptors[[]*Occurrence](ctx, oq, qr, oq.inters)
}

// AllX is like All, but panics if an error occurs.
func (oq *OccurrenceQuery) AllX(ctx context.Context) []*Occurrence {
	nodes, err := oq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of Occurrence IDs.
func (oq *OccurrenceQuery) IDs(ctx context.Context) (ids []int, err error) {
	if oq.ctx.Unique == nil && oq.path != nil {
		oq.Unique(true)
	}
	ctx = setContextOp(ctx, oq.ctx, "IDs")
	if err = oq.Select(occurrence.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (oq *OccurrenceQuery) IDsX(ctx context.Context) []int {
	ids, err := oq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (oq *OccurrenceQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, oq.ctx, "Count")
	if err := oq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, oq, querierCount[*OccurrenceQuery](), oq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (oq *OccurrenceQuery) CountX(ctx context.Context) int {
	count, err := oq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (oq *OccurrenceQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, oq.ctx, "Exist")
	switch _, err := oq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (oq *OccurrenceQuery) ExistX(ctx context.Context) bool {
	exist, err := oq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the OccurrenceQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (oq *OccurrenceQuery) Clone() *OccurrenceQuery {
	if oq == nil {
		return nil
	}
	return &OccurrenceQuery{
		config:       oq.config,
		ctx:          oq.ctx.Clone(),
		order:        append([]occurrence.OrderOption{}, oq.order...),
		inters:       append([]Interceptor{}, oq.inters...),
		predicates:   append([]predicate.Occurrence{}, oq.predicates...),
		withArtifact: oq.withArtifact.Clone(),
		withPackage:  oq.withPackage.Clone(),
		withSource:   oq.withSource.Clone(),
		// clone intermediate query.
		sql:  oq.sql.Clone(),
		path: oq.path,
	}
}

// WithArtifact tells the query-builder to eager-load the nodes that are connected to
// the "artifact" edge. The optional arguments are used to configure the query builder of the edge.
func (oq *OccurrenceQuery) WithArtifact(opts ...func(*ArtifactQuery)) *OccurrenceQuery {
	query := (&ArtifactClient{config: oq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	oq.withArtifact = query
	return oq
}

// WithPackage tells the query-builder to eager-load the nodes that are connected to
// the "package" edge. The optional arguments are used to configure the query builder of the edge.
func (oq *OccurrenceQuery) WithPackage(opts ...func(*PackageVersionQuery)) *OccurrenceQuery {
	query := (&PackageVersionClient{config: oq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	oq.withPackage = query
	return oq
}

// WithSource tells the query-builder to eager-load the nodes that are connected to
// the "source" edge. The optional arguments are used to configure the query builder of the edge.
func (oq *OccurrenceQuery) WithSource(opts ...func(*SourceNameQuery)) *OccurrenceQuery {
	query := (&SourceNameClient{config: oq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	oq.withSource = query
	return oq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		ArtifactID int `json:"artifact_id,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.Occurrence.Query().
//		GroupBy(occurrence.FieldArtifactID).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (oq *OccurrenceQuery) GroupBy(field string, fields ...string) *OccurrenceGroupBy {
	oq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &OccurrenceGroupBy{build: oq}
	grbuild.flds = &oq.ctx.Fields
	grbuild.label = occurrence.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		ArtifactID int `json:"artifact_id,omitempty"`
//	}
//
//	client.Occurrence.Query().
//		Select(occurrence.FieldArtifactID).
//		Scan(ctx, &v)
func (oq *OccurrenceQuery) Select(fields ...string) *OccurrenceSelect {
	oq.ctx.Fields = append(oq.ctx.Fields, fields...)
	sbuild := &OccurrenceSelect{OccurrenceQuery: oq}
	sbuild.label = occurrence.Label
	sbuild.flds, sbuild.scan = &oq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a OccurrenceSelect configured with the given aggregations.
func (oq *OccurrenceQuery) Aggregate(fns ...AggregateFunc) *OccurrenceSelect {
	return oq.Select().Aggregate(fns...)
}

func (oq *OccurrenceQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range oq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, oq); err != nil {
				return err
			}
		}
	}
	for _, f := range oq.ctx.Fields {
		if !occurrence.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if oq.path != nil {
		prev, err := oq.path(ctx)
		if err != nil {
			return err
		}
		oq.sql = prev
	}
	return nil
}

func (oq *OccurrenceQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*Occurrence, error) {
	var (
		nodes       = []*Occurrence{}
		_spec       = oq.querySpec()
		loadedTypes = [3]bool{
			oq.withArtifact != nil,
			oq.withPackage != nil,
			oq.withSource != nil,
		}
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*Occurrence).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &Occurrence{config: oq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	if len(oq.modifiers) > 0 {
		_spec.Modifiers = oq.modifiers
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, oq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := oq.withArtifact; query != nil {
		if err := oq.loadArtifact(ctx, query, nodes, nil,
			func(n *Occurrence, e *Artifact) { n.Edges.Artifact = e }); err != nil {
			return nil, err
		}
	}
	if query := oq.withPackage; query != nil {
		if err := oq.loadPackage(ctx, query, nodes, nil,
			func(n *Occurrence, e *PackageVersion) { n.Edges.Package = e }); err != nil {
			return nil, err
		}
	}
	if query := oq.withSource; query != nil {
		if err := oq.loadSource(ctx, query, nodes, nil,
			func(n *Occurrence, e *SourceName) { n.Edges.Source = e }); err != nil {
			return nil, err
		}
	}
	for i := range oq.loadTotal {
		if err := oq.loadTotal[i](ctx, nodes); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (oq *OccurrenceQuery) loadArtifact(ctx context.Context, query *ArtifactQuery, nodes []*Occurrence, init func(*Occurrence), assign func(*Occurrence, *Artifact)) error {
	ids := make([]int, 0, len(nodes))
	nodeids := make(map[int][]*Occurrence)
	for i := range nodes {
		fk := nodes[i].ArtifactID
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(artifact.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "artifact_id" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (oq *OccurrenceQuery) loadPackage(ctx context.Context, query *PackageVersionQuery, nodes []*Occurrence, init func(*Occurrence), assign func(*Occurrence, *PackageVersion)) error {
	ids := make([]int, 0, len(nodes))
	nodeids := make(map[int][]*Occurrence)
	for i := range nodes {
		if nodes[i].PackageID == nil {
			continue
		}
		fk := *nodes[i].PackageID
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(packageversion.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "package_id" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (oq *OccurrenceQuery) loadSource(ctx context.Context, query *SourceNameQuery, nodes []*Occurrence, init func(*Occurrence), assign func(*Occurrence, *SourceName)) error {
	ids := make([]int, 0, len(nodes))
	nodeids := make(map[int][]*Occurrence)
	for i := range nodes {
		if nodes[i].SourceID == nil {
			continue
		}
		fk := *nodes[i].SourceID
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(sourcename.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "source_id" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (oq *OccurrenceQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := oq.querySpec()
	if len(oq.modifiers) > 0 {
		_spec.Modifiers = oq.modifiers
	}
	_spec.Node.Columns = oq.ctx.Fields
	if len(oq.ctx.Fields) > 0 {
		_spec.Unique = oq.ctx.Unique != nil && *oq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, oq.driver, _spec)
}

func (oq *OccurrenceQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(occurrence.Table, occurrence.Columns, sqlgraph.NewFieldSpec(occurrence.FieldID, field.TypeInt))
	_spec.From = oq.sql
	if unique := oq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if oq.path != nil {
		_spec.Unique = true
	}
	if fields := oq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, occurrence.FieldID)
		for i := range fields {
			if fields[i] != occurrence.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
		if oq.withArtifact != nil {
			_spec.Node.AddColumnOnce(occurrence.FieldArtifactID)
		}
		if oq.withPackage != nil {
			_spec.Node.AddColumnOnce(occurrence.FieldPackageID)
		}
		if oq.withSource != nil {
			_spec.Node.AddColumnOnce(occurrence.FieldSourceID)
		}
	}
	if ps := oq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := oq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := oq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := oq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (oq *OccurrenceQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(oq.driver.Dialect())
	t1 := builder.Table(occurrence.Table)
	columns := oq.ctx.Fields
	if len(columns) == 0 {
		columns = occurrence.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if oq.sql != nil {
		selector = oq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if oq.ctx.Unique != nil && *oq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range oq.predicates {
		p(selector)
	}
	for _, p := range oq.order {
		p(selector)
	}
	if offset := oq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := oq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// OccurrenceGroupBy is the group-by builder for Occurrence entities.
type OccurrenceGroupBy struct {
	selector
	build *OccurrenceQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (ogb *OccurrenceGroupBy) Aggregate(fns ...AggregateFunc) *OccurrenceGroupBy {
	ogb.fns = append(ogb.fns, fns...)
	return ogb
}

// Scan applies the selector query and scans the result into the given value.
func (ogb *OccurrenceGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, ogb.build.ctx, "GroupBy")
	if err := ogb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*OccurrenceQuery, *OccurrenceGroupBy](ctx, ogb.build, ogb, ogb.build.inters, v)
}

func (ogb *OccurrenceGroupBy) sqlScan(ctx context.Context, root *OccurrenceQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(ogb.fns))
	for _, fn := range ogb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*ogb.flds)+len(ogb.fns))
		for _, f := range *ogb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*ogb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := ogb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// OccurrenceSelect is the builder for selecting fields of Occurrence entities.
type OccurrenceSelect struct {
	*OccurrenceQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (os *OccurrenceSelect) Aggregate(fns ...AggregateFunc) *OccurrenceSelect {
	os.fns = append(os.fns, fns...)
	return os
}

// Scan applies the selector query and scans the result into the given value.
func (os *OccurrenceSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, os.ctx, "Select")
	if err := os.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*OccurrenceQuery, *OccurrenceSelect](ctx, os.OccurrenceQuery, os, os.inters, v)
}

func (os *OccurrenceSelect) sqlScan(ctx context.Context, root *OccurrenceQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(os.fns))
	for _, fn := range os.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*os.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := os.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
