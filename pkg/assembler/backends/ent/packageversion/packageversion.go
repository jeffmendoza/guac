// Code generated by ent, DO NOT EDIT.

package packageversion

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
)

const (
	// Label holds the string label denoting the packageversion type in the database.
	Label = "package_version"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldNameID holds the string denoting the name_id field in the database.
	FieldNameID = "name_id"
	// FieldVersion holds the string denoting the version field in the database.
	FieldVersion = "version"
	// EdgeName holds the string denoting the name edge name in mutations.
	EdgeName = "name"
	// Table holds the table name of the packageversion in the database.
	Table = "package_versions"
	// NameTable is the table that holds the name relation/edge.
	NameTable = "package_versions"
	// NameInverseTable is the table name for the PackageName entity.
	// It exists in this package in order to avoid circular dependency with the "packagename" package.
	NameInverseTable = "package_names"
	// NameColumn is the table column denoting the name relation/edge.
	NameColumn = "name_id"
)

// Columns holds all SQL columns for packageversion fields.
var Columns = []string{
	FieldID,
	FieldNameID,
	FieldVersion,
}

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	return false
}

var (
	// VersionValidator is a validator for the "version" field. It is called by the builders before save.
	VersionValidator func(string) error
)

// OrderOption defines the ordering options for the PackageVersion queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByNameID orders the results by the name_id field.
func ByNameID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldNameID, opts...).ToFunc()
}

// ByVersion orders the results by the version field.
func ByVersion(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldVersion, opts...).ToFunc()
}

// ByNameField orders the results by name field.
func ByNameField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newNameStep(), sql.OrderByField(field, opts...))
	}
}
func newNameStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(NameInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, true, NameTable, NameColumn),
	)
}