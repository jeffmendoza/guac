// Code generated by ent, DO NOT EDIT.

package ent

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/builder"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/slsaattestation"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// SLSAAttestation is the model entity for the SLSAAttestation schema.
type SLSAAttestation struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// Type of the builder
	BuildType string `json:"build_type,omitempty"`
	// ID of the builder
	BuiltByID int `json:"built_by_id,omitempty"`
	// ID of the subject artifact
	SubjectID int `json:"subject_id,omitempty"`
	// Individual predicates found in the attestation
	SlsaPredicate []*model.SLSAPredicate `json:"slsa_predicate,omitempty"`
	// Version of the SLSA predicate
	SlsaVersion string `json:"slsa_version,omitempty"`
	// Timestamp of build start time
	StartedOn *time.Time `json:"started_on,omitempty"`
	// Timestamp of build end time
	FinishedOn *time.Time `json:"finished_on,omitempty"`
	// Document from which this attestation is generated from
	Origin string `json:"origin,omitempty"`
	// GUAC collector for the document
	Collector string `json:"collector,omitempty"`
	// Hash of the artifacts that was built
	BuiltFromHash string `json:"built_from_hash,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the SLSAAttestationQuery when eager-loading is set.
	Edges        SLSAAttestationEdges `json:"edges"`
	selectValues sql.SelectValues
}

// SLSAAttestationEdges holds the relations/edges for other nodes in the graph.
type SLSAAttestationEdges struct {
	// BuiltFrom holds the value of the built_from edge.
	BuiltFrom []*Artifact `json:"built_from,omitempty"`
	// BuiltBy holds the value of the built_by edge.
	BuiltBy *Builder `json:"built_by,omitempty"`
	// Subject holds the value of the subject edge.
	Subject *Artifact `json:"subject,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [3]bool
	// totalCount holds the count of the edges above.
	totalCount [3]map[string]int

	namedBuiltFrom map[string][]*Artifact
}

// BuiltFromOrErr returns the BuiltFrom value or an error if the edge
// was not loaded in eager-loading.
func (e SLSAAttestationEdges) BuiltFromOrErr() ([]*Artifact, error) {
	if e.loadedTypes[0] {
		return e.BuiltFrom, nil
	}
	return nil, &NotLoadedError{edge: "built_from"}
}

// BuiltByOrErr returns the BuiltBy value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e SLSAAttestationEdges) BuiltByOrErr() (*Builder, error) {
	if e.loadedTypes[1] {
		if e.BuiltBy == nil {
			// Edge was loaded but was not found.
			return nil, &NotFoundError{label: builder.Label}
		}
		return e.BuiltBy, nil
	}
	return nil, &NotLoadedError{edge: "built_by"}
}

// SubjectOrErr returns the Subject value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e SLSAAttestationEdges) SubjectOrErr() (*Artifact, error) {
	if e.loadedTypes[2] {
		if e.Subject == nil {
			// Edge was loaded but was not found.
			return nil, &NotFoundError{label: artifact.Label}
		}
		return e.Subject, nil
	}
	return nil, &NotLoadedError{edge: "subject"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*SLSAAttestation) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case slsaattestation.FieldSlsaPredicate:
			values[i] = new([]byte)
		case slsaattestation.FieldID, slsaattestation.FieldBuiltByID, slsaattestation.FieldSubjectID:
			values[i] = new(sql.NullInt64)
		case slsaattestation.FieldBuildType, slsaattestation.FieldSlsaVersion, slsaattestation.FieldOrigin, slsaattestation.FieldCollector, slsaattestation.FieldBuiltFromHash:
			values[i] = new(sql.NullString)
		case slsaattestation.FieldStartedOn, slsaattestation.FieldFinishedOn:
			values[i] = new(sql.NullTime)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the SLSAAttestation fields.
func (sa *SLSAAttestation) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case slsaattestation.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			sa.ID = int(value.Int64)
		case slsaattestation.FieldBuildType:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field build_type", values[i])
			} else if value.Valid {
				sa.BuildType = value.String
			}
		case slsaattestation.FieldBuiltByID:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field built_by_id", values[i])
			} else if value.Valid {
				sa.BuiltByID = int(value.Int64)
			}
		case slsaattestation.FieldSubjectID:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field subject_id", values[i])
			} else if value.Valid {
				sa.SubjectID = int(value.Int64)
			}
		case slsaattestation.FieldSlsaPredicate:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field slsa_predicate", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &sa.SlsaPredicate); err != nil {
					return fmt.Errorf("unmarshal field slsa_predicate: %w", err)
				}
			}
		case slsaattestation.FieldSlsaVersion:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field slsa_version", values[i])
			} else if value.Valid {
				sa.SlsaVersion = value.String
			}
		case slsaattestation.FieldStartedOn:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field started_on", values[i])
			} else if value.Valid {
				sa.StartedOn = new(time.Time)
				*sa.StartedOn = value.Time
			}
		case slsaattestation.FieldFinishedOn:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field finished_on", values[i])
			} else if value.Valid {
				sa.FinishedOn = new(time.Time)
				*sa.FinishedOn = value.Time
			}
		case slsaattestation.FieldOrigin:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field origin", values[i])
			} else if value.Valid {
				sa.Origin = value.String
			}
		case slsaattestation.FieldCollector:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field collector", values[i])
			} else if value.Valid {
				sa.Collector = value.String
			}
		case slsaattestation.FieldBuiltFromHash:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field built_from_hash", values[i])
			} else if value.Valid {
				sa.BuiltFromHash = value.String
			}
		default:
			sa.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the SLSAAttestation.
// This includes values selected through modifiers, order, etc.
func (sa *SLSAAttestation) Value(name string) (ent.Value, error) {
	return sa.selectValues.Get(name)
}

// QueryBuiltFrom queries the "built_from" edge of the SLSAAttestation entity.
func (sa *SLSAAttestation) QueryBuiltFrom() *ArtifactQuery {
	return NewSLSAAttestationClient(sa.config).QueryBuiltFrom(sa)
}

// QueryBuiltBy queries the "built_by" edge of the SLSAAttestation entity.
func (sa *SLSAAttestation) QueryBuiltBy() *BuilderQuery {
	return NewSLSAAttestationClient(sa.config).QueryBuiltBy(sa)
}

// QuerySubject queries the "subject" edge of the SLSAAttestation entity.
func (sa *SLSAAttestation) QuerySubject() *ArtifactQuery {
	return NewSLSAAttestationClient(sa.config).QuerySubject(sa)
}

// Update returns a builder for updating this SLSAAttestation.
// Note that you need to call SLSAAttestation.Unwrap() before calling this method if this SLSAAttestation
// was returned from a transaction, and the transaction was committed or rolled back.
func (sa *SLSAAttestation) Update() *SLSAAttestationUpdateOne {
	return NewSLSAAttestationClient(sa.config).UpdateOne(sa)
}

// Unwrap unwraps the SLSAAttestation entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (sa *SLSAAttestation) Unwrap() *SLSAAttestation {
	_tx, ok := sa.config.driver.(*txDriver)
	if !ok {
		panic("ent: SLSAAttestation is not a transactional entity")
	}
	sa.config.driver = _tx.drv
	return sa
}

// String implements the fmt.Stringer.
func (sa *SLSAAttestation) String() string {
	var builder strings.Builder
	builder.WriteString("SLSAAttestation(")
	builder.WriteString(fmt.Sprintf("id=%v, ", sa.ID))
	builder.WriteString("build_type=")
	builder.WriteString(sa.BuildType)
	builder.WriteString(", ")
	builder.WriteString("built_by_id=")
	builder.WriteString(fmt.Sprintf("%v", sa.BuiltByID))
	builder.WriteString(", ")
	builder.WriteString("subject_id=")
	builder.WriteString(fmt.Sprintf("%v", sa.SubjectID))
	builder.WriteString(", ")
	builder.WriteString("slsa_predicate=")
	builder.WriteString(fmt.Sprintf("%v", sa.SlsaPredicate))
	builder.WriteString(", ")
	builder.WriteString("slsa_version=")
	builder.WriteString(sa.SlsaVersion)
	builder.WriteString(", ")
	if v := sa.StartedOn; v != nil {
		builder.WriteString("started_on=")
		builder.WriteString(v.Format(time.ANSIC))
	}
	builder.WriteString(", ")
	if v := sa.FinishedOn; v != nil {
		builder.WriteString("finished_on=")
		builder.WriteString(v.Format(time.ANSIC))
	}
	builder.WriteString(", ")
	builder.WriteString("origin=")
	builder.WriteString(sa.Origin)
	builder.WriteString(", ")
	builder.WriteString("collector=")
	builder.WriteString(sa.Collector)
	builder.WriteString(", ")
	builder.WriteString("built_from_hash=")
	builder.WriteString(sa.BuiltFromHash)
	builder.WriteByte(')')
	return builder.String()
}

// NamedBuiltFrom returns the BuiltFrom named value or an error if the edge was not
// loaded in eager-loading with this name.
func (sa *SLSAAttestation) NamedBuiltFrom(name string) ([]*Artifact, error) {
	if sa.Edges.namedBuiltFrom == nil {
		return nil, &NotLoadedError{edge: name}
	}
	nodes, ok := sa.Edges.namedBuiltFrom[name]
	if !ok {
		return nil, &NotLoadedError{edge: name}
	}
	return nodes, nil
}

func (sa *SLSAAttestation) appendNamedBuiltFrom(name string, edges ...*Artifact) {
	if sa.Edges.namedBuiltFrom == nil {
		sa.Edges.namedBuiltFrom = make(map[string][]*Artifact)
	}
	if len(edges) == 0 {
		sa.Edges.namedBuiltFrom[name] = []*Artifact{}
	} else {
		sa.Edges.namedBuiltFrom[name] = append(sa.Edges.namedBuiltFrom[name], edges...)
	}
}

// SLSAAttestations is a parsable slice of SLSAAttestation.
type SLSAAttestations []*SLSAAttestation
