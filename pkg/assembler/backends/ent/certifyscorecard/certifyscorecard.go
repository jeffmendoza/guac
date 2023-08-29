// Code generated by ent, DO NOT EDIT.

package certifyscorecard

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
)

const (
	// Label holds the string label denoting the certifyscorecard type in the database.
	Label = "certify_scorecard"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldSourceID holds the string denoting the source_id field in the database.
	FieldSourceID = "source_id"
	// FieldScorecardID holds the string denoting the scorecard_id field in the database.
	FieldScorecardID = "scorecard_id"
	// EdgeScorecard holds the string denoting the scorecard edge name in mutations.
	EdgeScorecard = "scorecard"
	// EdgeSource holds the string denoting the source edge name in mutations.
	EdgeSource = "source"
	// Table holds the table name of the certifyscorecard in the database.
	Table = "certify_scorecards"
	// ScorecardTable is the table that holds the scorecard relation/edge.
	ScorecardTable = "certify_scorecards"
	// ScorecardInverseTable is the table name for the Scorecard entity.
	// It exists in this package in order to avoid circular dependency with the "scorecard" package.
	ScorecardInverseTable = "scorecards"
	// ScorecardColumn is the table column denoting the scorecard relation/edge.
	ScorecardColumn = "scorecard_id"
	// SourceTable is the table that holds the source relation/edge.
	SourceTable = "certify_scorecards"
	// SourceInverseTable is the table name for the SourceName entity.
	// It exists in this package in order to avoid circular dependency with the "sourcename" package.
	SourceInverseTable = "source_names"
	// SourceColumn is the table column denoting the source relation/edge.
	SourceColumn = "source_id"
)

// Columns holds all SQL columns for certifyscorecard fields.
var Columns = []string{
	FieldID,
	FieldSourceID,
	FieldScorecardID,
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

// OrderOption defines the ordering options for the CertifyScorecard queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// BySourceID orders the results by the source_id field.
func BySourceID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldSourceID, opts...).ToFunc()
}

// ByScorecardID orders the results by the scorecard_id field.
func ByScorecardID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldScorecardID, opts...).ToFunc()
}

// ByScorecardField orders the results by scorecard field.
func ByScorecardField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newScorecardStep(), sql.OrderByField(field, opts...))
	}
}

// BySourceField orders the results by source field.
func BySourceField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newSourceStep(), sql.OrderByField(field, opts...))
	}
}
func newScorecardStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(ScorecardInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, true, ScorecardTable, ScorecardColumn),
	)
}
func newSourceStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(SourceInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, false, SourceTable, SourceColumn),
	)
}
