package tests

// Usually this would be part of ent, but the import cycle doesn't allow for it.

import (
	"testing"

	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenode"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/testutils"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/stretchr/testify/suite"
)

type Suite struct {
	testutils.Suite
}

func TestSoftwareTreeSuite(t *testing.T) {
	suite.Run(t, new(Suite))
}

func (s *Suite) TestCreateSoftwareTree() {
	be, err := ent.GetBackend(ent.WithEntClient(s.Client))
	s.NoError(err)

	// pkg:apk/alpine/apk@2.12.9-r3?arch=x86
	pkg, err := be.IngestPackage(s.Ctx, model.PkgInputSpec{
		Type:      "apk",
		Namespace: ptr("alpine"),
		Name:      "apk",
		Version:   ptr("2.12.9-r3"),
		Subpath:   nil,
		Qualifiers: []*model.PackageQualifierInputSpec{
			{Key: "arch", Value: "x86"},
		},
	})
	s.NoError(err)
	s.NotNil(pkg)
	s.Equal("apk", pkg.Type)

	if s.Len(pkg.Namespaces, 1) {
		s.Equal("alpine", pkg.Namespaces[0].Namespace)

		if s.Len(pkg.Namespaces[0].Names, 1) {
			s.Equal("apk", pkg.Namespaces[0].Names[0].Name)

			if s.Len(pkg.Namespaces[0].Names[0].Versions, 1) {
				s.Equal("2.12.9-r3", pkg.Namespaces[0].Names[0].Versions[0].Version)
			}
		}
	}

	// Ingest a second time should only create a new version
	pkg, err = be.IngestPackage(s.Ctx, model.PkgInputSpec{
		Type:      "apk",
		Namespace: ptr("alpine"),
		Name:      "apk",
		Version:   ptr("2.12.10"),
		Subpath:   nil,
		Qualifiers: []*model.PackageQualifierInputSpec{
			{Key: "arch", Value: "x86"},
		},
	})
	// Ensure that we don't get a duplicate row error
	s.NoError(err)

	pkgTree := s.Client.PackageNode.Query().Where(packagenode.Type("apk")).
		WithNamespaces(func(q *ent.PackageNamespaceQuery) {
			q.WithNames(func(q *ent.PackageNameQuery) {
				q.WithVersions()
			})
		}).
		FirstX(s.Ctx)

	s.NotNil(pkgTree)
}

func ptr[T any](s T) *T {
	return &s
}