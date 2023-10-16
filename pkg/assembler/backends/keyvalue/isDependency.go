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

package keyvalue

import (
	"context"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Internal data: link between packages and dependent packages (isDependency)
type isDependencyList []*isDependencyLink
type isDependencyLink struct {
	id             string
	packageID      string
	depPackageID   string
	versionRange   string
	dependencyType model.DependencyType
	justification  string
	origin         string
	collector      string
}

func (n *isDependencyLink) ID() string  { return n.id }
func (n *isDependencyLink) Key() string { return n.id }

func (n *isDependencyLink) Neighbors(allowedEdges edgeMap) []string {
	if allowedEdges[model.EdgeIsDependencyPackage] {
		return []string{n.packageID, n.depPackageID}
	}
	return []string{}
}

func (n *isDependencyLink) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildIsDependency(ctx, n, nil, true)
}

// Ingest IngestDependencies

func (c *demoClient) IngestDependencies(ctx context.Context, pkgs []*model.PkgInputSpec, depPkgs []*model.PkgInputSpec, depPkgMatchType model.MatchFlags, dependencies []*model.IsDependencyInputSpec) ([]*model.IsDependency, error) {
	// TODO(LUMJJB): match flags

	var modelIsDependencies []*model.IsDependency
	for i := range dependencies {
		isDependency, err := c.IngestDependency(ctx, *pkgs[i], *depPkgs[i], depPkgMatchType, *dependencies[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestDependency failed with err: %v", err)
		}
		modelIsDependencies = append(modelIsDependencies, isDependency)
	}
	return modelIsDependencies, nil
}

// Ingest IsDependency
func (c *demoClient) IngestDependency(ctx context.Context, packageArg model.PkgInputSpec, dependentPackageArg model.PkgInputSpec, depPkgMatchType model.MatchFlags, dependency model.IsDependencyInputSpec) (*model.IsDependency, error) {
	return c.ingestDependency(ctx, packageArg, dependentPackageArg, depPkgMatchType, dependency, true)
}

func (c *demoClient) ingestDependency(ctx context.Context, packageArg model.PkgInputSpec, dependentPackageArg model.PkgInputSpec, depPkgMatchType model.MatchFlags, dependency model.IsDependencyInputSpec, readOnly bool) (*model.IsDependency, error) {
	funcName := "IngestDependency"
	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	// for IsDependency the dependent package will return the ID at the
	// packageName node. VersionRange will be used to specify the versions are
	// the attestation relates to
	foundPkgVersion, err := c.getPackageVerFromInput(ctx, packageArg)
	if err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	packageDependencies := foundPkgVersion.IsDependencyLinks

	depPkg, err := c.getPackageNameOrVerFromInput(ctx, dependentPackageArg, depPkgMatchType)
	if err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	depPackageDependencies := depPkg.getIsDependencyLinks()

	var searchIDs []string
	if len(packageDependencies) < len(depPackageDependencies) {
		searchIDs = packageDependencies
	} else {
		searchIDs = depPackageDependencies
	}

	// Don't insert duplicates
	duplicate := false
	collectedIsDependencyLink := isDependencyLink{}
	for _, id := range searchIDs {
		v, err := byID[*isDependencyLink](id, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		if foundPkgVersion.ThisID == v.packageID && depPkg.ID() == v.depPackageID && dependency.Justification == v.justification &&
			dependency.Origin == v.origin && dependency.Collector == v.collector &&
			dependency.VersionRange == v.versionRange && dependency.DependencyType == v.dependencyType {

			collectedIsDependencyLink = *v
			duplicate = true
			break
		}
	}
	if !duplicate {
		if readOnly {
			c.m.RUnlock()
			d, err := c.ingestDependency(ctx, packageArg, dependentPackageArg, depPkgMatchType, dependency, false)
			c.m.RLock() // relock so that defer unlock does not panic
			return d, err
		}
		// store the link
		collectedIsDependencyLink = isDependencyLink{
			id:             c.getNextID(),
			packageID:      foundPkgVersion.ThisID,
			depPackageID:   depPkg.ID(),
			versionRange:   dependency.VersionRange,
			dependencyType: dependency.DependencyType,
			justification:  dependency.Justification,
			origin:         dependency.Origin,
			collector:      dependency.Collector,
		}
		c.index[collectedIsDependencyLink.id] = &collectedIsDependencyLink
		c.isDependencies = append(c.isDependencies, &collectedIsDependencyLink)
		// set the backlinks
		foundPkgVersion.setIsDependencyLinks(collectedIsDependencyLink.id)
		depPkg.setIsDependencyLinks(collectedIsDependencyLink.id)
	}

	// build return GraphQL type
	foundIsDependency, err := c.buildIsDependency(ctx, &collectedIsDependencyLink, nil, true)
	if err != nil {
		return nil, err
	}

	return foundIsDependency, nil
}

// Query IsDependency
func (c *demoClient) IsDependency(ctx context.Context, filter *model.IsDependencySpec) ([]*model.IsDependency, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	funcName := "IsDependency"
	if filter != nil && filter.ID != nil {
		link, err := byID[*isDependencyLink](*filter.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		foundIsDependency, err := c.buildIsDependency(ctx, link, filter, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.IsDependency{foundIsDependency}, nil
	}

	var search []string
	foundOne := false
	if filter != nil && filter.Package != nil {
		pkgs, err := c.findPackageVersion(ctx, filter.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		foundOne = len(pkgs) > 0
		for _, pkg := range pkgs {
			search = append(search, pkg.IsDependencyLinks...)
		}
	}
	if !foundOne && filter != nil && filter.DependencyPackage != nil {
		if filter.DependencyPackage.Version == nil {
			exactPackage, err := c.exactPackageName(ctx, filter.DependencyPackage)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			if exactPackage != nil {
				search = append(search, exactPackage.IsDependencyLinks...)
				foundOne = true
			}
		} else {
			pkgs, err := c.findPackageVersion(ctx, filter.Package)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			foundOne = len(pkgs) > 0
			for _, pkg := range pkgs {
				search = append(search, pkg.IsDependencyLinks...)
			}
		}
	}

	var out []*model.IsDependency
	if foundOne {
		for _, id := range search {
			link, err := byID[*isDependencyLink](id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addDepIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		for _, link := range c.isDependencies {
			var err error
			out, err = c.addDepIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}

	return out, nil
}

func (c *demoClient) buildIsDependency(ctx context.Context, link *isDependencyLink, filter *model.IsDependencySpec, ingestOrIDProvided bool) (*model.IsDependency, error) {
	var p *model.Package
	var dep *model.Package
	var err error
	if filter != nil {
		p, err = c.buildPackageResponse(ctx, link.packageID, filter.Package)
		if err != nil {
			return nil, err
		}
	} else {
		p, err = c.buildPackageResponse(ctx, link.packageID, nil)
		if err != nil {
			return nil, err
		}
	}
	if filter != nil && filter.DependencyPackage != nil {
		depPkgFilter := &model.PkgSpec{Type: filter.DependencyPackage.Type, Namespace: filter.DependencyPackage.Namespace,
			Name: filter.DependencyPackage.Name}
		dep, err = c.buildPackageResponse(ctx, link.depPackageID, depPkgFilter)
		if err != nil {
			return nil, err
		}
	} else {
		dep, err = c.buildPackageResponse(ctx, link.depPackageID, nil)
		if err != nil {
			return nil, err
		}
	}

	// if package not found during ingestion or if ID is provided in filter, send error. On query do not send error to continue search
	if p == nil && ingestOrIDProvided {
		return nil, gqlerror.Errorf("failed to retrieve package via packageID")
	} else if p == nil && !ingestOrIDProvided {
		return nil, nil
	}
	// if dependent package not found during ingestion or if ID is provided in filter, send error. On query do not send error to continue search
	if dep == nil && ingestOrIDProvided {
		return nil, gqlerror.Errorf("failed to retrieve dependent package via dependent packageID")
	} else if dep == nil && !ingestOrIDProvided {
		return nil, nil
	}

	foundIsDependency := model.IsDependency{
		ID:                link.id,
		Package:           p,
		DependencyPackage: dep,
		VersionRange:      link.versionRange,
		DependencyType:    link.dependencyType,
		Justification:     link.justification,
		Origin:            link.origin,
		Collector:         link.collector,
	}
	return &foundIsDependency, nil
}

func (c *demoClient) addDepIfMatch(ctx context.Context, out []*model.IsDependency,
	filter *model.IsDependencySpec, link *isDependencyLink) (
	[]*model.IsDependency, error) {
	if filter != nil && noMatch(filter.Justification, link.justification) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Origin, link.origin) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Collector, link.collector) {
		return out, nil
	}
	if filter != nil && noMatch(filter.VersionRange, link.versionRange) {
		return out, nil
	}
	if filter != nil && filter.DependencyType != nil && *filter.DependencyType != link.dependencyType {
		return out, nil
	}

	foundIsDependency, err := c.buildIsDependency(ctx, link, filter, false)
	if err != nil {
		return nil, err
	}
	if foundIsDependency == nil {
		return out, nil
	}
	return append(out, foundIsDependency), nil
}