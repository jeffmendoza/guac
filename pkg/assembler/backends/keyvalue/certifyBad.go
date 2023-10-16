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
	"time"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// TODO: update the other backends to handle the new timestamp fields beacuse of: https://github.com/guacsec/guac/pull/1338/files#r1343080326

// Internal data: link that a package/source/artifact is bad
type badList []*badLink
type badLink struct {
	id            string
	packageID     string
	artifactID    string
	sourceID      string
	justification string
	origin        string
	collector     string
	knownSince    time.Time
}

func (n *badLink) Key() string {
	return ""
}

func (n *badLink) ID() string { return n.id }

func (n *badLink) Neighbors(allowedEdges edgeMap) []string {
	out := make([]string, 0, 1)
	if n.packageID != "" && allowedEdges[model.EdgeCertifyBadPackage] {
		out = append(out, n.packageID)
	}
	if n.artifactID != "" && allowedEdges[model.EdgeCertifyBadArtifact] {
		out = append(out, n.artifactID)
	}
	if n.sourceID != "" && allowedEdges[model.EdgeCertifyBadSource] {
		out = append(out, n.sourceID)
	}
	return out
}

func (n *badLink) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildCertifyBad(ctx, n, nil, true)
}

// Ingest CertifyBad
func (c *demoClient) IngestCertifyBads(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, certifyBads []*model.CertifyBadInputSpec) ([]*model.CertifyBad, error) {
	var modelCertifyBads []*model.CertifyBad

	for i := range certifyBads {
		var certifyBad *model.CertifyBad
		var err error
		if len(subjects.Packages) > 0 {
			subject := model.PackageSourceOrArtifactInput{Package: subjects.Packages[i]}
			certifyBad, err = c.IngestCertifyBad(ctx, subject, pkgMatchType, *certifyBads[i])
			if err != nil {
				return nil, gqlerror.Errorf("IngestCertifyBad failed with err: %v", err)
			}
		} else if len(subjects.Sources) > 0 {
			subject := model.PackageSourceOrArtifactInput{Source: subjects.Sources[i]}
			certifyBad, err = c.IngestCertifyBad(ctx, subject, pkgMatchType, *certifyBads[i])
			if err != nil {
				return nil, gqlerror.Errorf("IngestCertifyBad failed with err: %v", err)
			}
		} else {
			subject := model.PackageSourceOrArtifactInput{Artifact: subjects.Artifacts[i]}
			certifyBad, err = c.IngestCertifyBad(ctx, subject, pkgMatchType, *certifyBads[i])
			if err != nil {
				return nil, gqlerror.Errorf("IngestCertifyBad failed with err: %v", err)
			}
		}
		modelCertifyBads = append(modelCertifyBads, certifyBad)
	}
	return modelCertifyBads, nil
}

func (c *demoClient) IngestCertifyBad(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyBad model.CertifyBadInputSpec) (*model.CertifyBad, error) {
	return c.ingestCertifyBad(ctx, subject, pkgMatchType, certifyBad, true)
}
func (c *demoClient) ingestCertifyBad(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyBad model.CertifyBadInputSpec, readOnly bool) (*model.CertifyBad, error) {
	funcName := "IngestCertifyBad"

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	var packageID string
	var foundPkgNameorVersionNode pkgNameOrVersion
	var foundArtStruct *artStruct
	var sourceID string
	var srcName *srcNameNode
	var searchIDs []string
	if subject.Package != nil {
		var err error
		foundPkgNameorVersionNode, err = c.getPackageNameOrVerFromInput(ctx, *subject.Package, *pkgMatchType)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		searchIDs = foundPkgNameorVersionNode.getCertifyBadLinks()
	} else if subject.Artifact != nil {
		var err error
		foundArtStruct, err = c.artifactByInput(ctx, subject.Artifact)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		searchIDs = foundArtStruct.badLinks
	} else {
		var err error
		sourceID, err = getSourceIDFromInput(c, *subject.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		srcName, err = byID[*srcNameNode](sourceID, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		searchIDs = srcName.badLinks
	}

	// Don't insert duplicates
	duplicate := false
	collectedCertifyBadLink := badLink{}
	for _, id := range searchIDs {
		v, err := byID[*badLink](id, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		subjectMatch := false
		if packageID != "" && packageID == v.packageID {
			subjectMatch = true
		}
		if foundArtStruct != nil && foundArtStruct.ThisID == v.artifactID {
			subjectMatch = true
		}
		if sourceID != "" && sourceID == v.sourceID {
			subjectMatch = true
		}
		if subjectMatch && certifyBad.Justification == v.justification &&
			certifyBad.Origin == v.origin && certifyBad.Collector == v.collector &&
			certifyBad.KnownSince.Equal(v.knownSince) {

			collectedCertifyBadLink = *v
			duplicate = true
			break
		}
	}
	if !duplicate {
		if readOnly {
			c.m.RUnlock()
			b, err := c.ingestCertifyBad(ctx, subject, pkgMatchType, certifyBad, false)
			c.m.RLock() // relock so that defer unlock does not panic
			return b, err
		}
		// store the link
		collectedCertifyBadLink = badLink{
			id:            c.getNextID(),
			packageID:     packageID,
			artifactID:    foundArtStruct.ThisID,
			sourceID:      sourceID,
			justification: certifyBad.Justification,
			origin:        certifyBad.Origin,
			collector:     certifyBad.Collector,
			knownSince:    certifyBad.KnownSince.UTC(),
		}
		c.index[collectedCertifyBadLink.id] = &collectedCertifyBadLink
		c.certifyBads = append(c.certifyBads, &collectedCertifyBadLink)
		// set the backlinks
		if packageID != "" {
			foundPkgNameorVersionNode.setCertifyBadLinks(collectedCertifyBadLink.id)
		}
		if foundArtStruct != nil {
			foundArtStruct.setCertifyBadLinks(collectedCertifyBadLink.id)
		}
		if sourceID != "" {
			srcName.setCertifyBadLinks(collectedCertifyBadLink.id)
		}

	}

	// build return GraphQL type
	builtCertifyBad, err := c.buildCertifyBad(ctx, &collectedCertifyBadLink, nil, true)
	if err != nil {
		return nil, err
	}
	return builtCertifyBad, nil
}

// Query CertifyBad
func (c *demoClient) CertifyBad(ctx context.Context, filter *model.CertifyBadSpec) ([]*model.CertifyBad, error) {
	funcName := "CertifyBad"

	c.m.RLock()
	defer c.m.RUnlock()

	if filter != nil && filter.ID != nil {
		link, err := byID[*badLink](*filter.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		foundCertifyBad, err := c.buildCertifyBad(ctx, link, filter, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.CertifyBad{foundCertifyBad}, nil
	}

	// Cant really search for an exact Pkg, as these can be linked to either
	// names or versions, and version could be empty.
	var search []string
	foundOne := false
	if filter != nil && filter.Subject != nil && filter.Subject.Artifact != nil {
		exactArtifact, err := c.artifactExact(ctx, filter.Subject.Artifact)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactArtifact != nil {
			search = append(search, exactArtifact.badLinks...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil && filter.Subject != nil && filter.Subject.Source != nil {
		exactSource, err := c.exactSource(filter.Subject.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactSource != nil {
			search = append(search, exactSource.badLinks...)
			foundOne = true
		}
	}

	var out []*model.CertifyBad
	if foundOne {
		for _, id := range search {
			link, err := byID[*badLink](id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addCBIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		for _, link := range c.certifyBads {
			var err error
			out, err = c.addCBIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}
	return out, nil
}

func (c *demoClient) addCBIfMatch(ctx context.Context, out []*model.CertifyBad,
	filter *model.CertifyBadSpec, link *badLink) (
	[]*model.CertifyBad, error) {

	if filter != nil {
		if noMatch(filter.Justification, link.justification) ||
			noMatch(filter.Collector, link.collector) ||
			noMatch(filter.Origin, link.origin) ||
			(filter.KnownSince != nil && filter.KnownSince.After(link.knownSince)) {
			return out, nil
		}
	}

	foundCertifyBad, err := c.buildCertifyBad(ctx, link, filter, false)
	if err != nil {
		return nil, err
	}
	if foundCertifyBad == nil {
		return out, nil
	}
	return append(out, foundCertifyBad), nil
}

func (c *demoClient) buildCertifyBad(ctx context.Context, link *badLink, filter *model.CertifyBadSpec, ingestOrIDProvided bool) (*model.CertifyBad, error) {
	var p *model.Package
	var a *model.Artifact
	var s *model.Source
	var err error
	if filter != nil && filter.Subject != nil {
		if filter.Subject.Package != nil && link.packageID != "" {
			p, err = c.buildPackageResponse(ctx, link.packageID, filter.Subject.Package)
			if err != nil {
				return nil, err
			}
		}
		if filter.Subject.Artifact != nil && link.artifactID != "" {
			a, err = c.buildArtifactResponse(ctx, link.artifactID, filter.Subject.Artifact)
			if err != nil {
				return nil, err
			}
		}
		if filter.Subject.Source != nil && link.sourceID != "" {
			s, err = c.buildSourceResponse(link.sourceID, filter.Subject.Source)
			if err != nil {
				return nil, err
			}
		}
	} else {
		if link.packageID != "" {
			p, err = c.buildPackageResponse(ctx, link.packageID, nil)
			if err != nil {
				return nil, err
			}
		}
		if link.artifactID != "" {
			a, err = c.buildArtifactResponse(ctx, link.artifactID, nil)
			if err != nil {
				return nil, err
			}
		}
		if link.sourceID != "" {
			s, err = c.buildSourceResponse(link.sourceID, nil)
			if err != nil {
				return nil, err
			}
		}
	}

	var subj model.PackageSourceOrArtifact
	if link.packageID != "" {
		if p == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve package via packageID")
		} else if p == nil && !ingestOrIDProvided {
			return nil, nil
		}
		subj = p
	}
	if link.artifactID != "" {
		if a == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve artifact via artifactID")
		} else if a == nil && !ingestOrIDProvided {
			return nil, nil
		}
		subj = a
	}
	if link.sourceID != "" {
		if s == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve source via sourceID")
		} else if s == nil && !ingestOrIDProvided {
			return nil, nil
		}
		subj = s
	}

	certifyBad := model.CertifyBad{
		ID:            link.id,
		Subject:       subj,
		Justification: link.justification,
		Origin:        link.origin,
		Collector:     link.collector,
		KnownSince:    link.knownSince.UTC(),
	}
	return &certifyBad, nil
}