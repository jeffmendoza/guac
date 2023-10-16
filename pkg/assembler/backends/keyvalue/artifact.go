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
	"fmt"
	"strings"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Internal data: Artifacts
type artMap map[string]*artStruct
type artStruct struct {
	ThisID              string
	Algorithm           string
	Digest              string
	hashEquals          []string
	Occurrences         []string
	hasSBOMs            []string
	hasSLSAs            []string
	vexLinks            []string
	badLinks            []string
	goodLinks           []string
	hasMetadataLinks    []string
	pointOfContactLinks []string
}

func (n *artStruct) ID() string { return n.ThisID }

func (n *artStruct) Neighbors(allowedEdges edgeMap) []string {
	out := []string{}
	if allowedEdges[model.EdgeArtifactHashEqual] {
		out = append(out, n.hashEquals...)
	}
	if allowedEdges[model.EdgeArtifactIsOccurrence] {
		out = append(out, n.Occurrences...)
	}
	if allowedEdges[model.EdgeArtifactHasSbom] {
		out = append(out, n.hasSBOMs...)
	}
	if allowedEdges[model.EdgeArtifactHasSlsa] {
		out = append(out, n.hasSLSAs...)
	}
	if allowedEdges[model.EdgeArtifactCertifyVexStatement] {
		out = append(out, n.vexLinks...)
	}
	if allowedEdges[model.EdgeArtifactCertifyBad] {
		out = append(out, n.badLinks...)
	}
	if allowedEdges[model.EdgeArtifactCertifyGood] {
		out = append(out, n.goodLinks...)
	}
	if allowedEdges[model.EdgeArtifactHasMetadata] {
		out = append(out, n.hasMetadataLinks...)
	}
	if allowedEdges[model.EdgeArtifactPointOfContact] {
		out = append(out, n.pointOfContactLinks...)
	}

	return out
}

func (n *artStruct) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.convArtifact(n), nil
}

func (n *artStruct) setHashEquals(ID string) { n.hashEquals = append(n.hashEquals, ID) }

// func (n *artStruct) setOccurrences(ID string)      { n.occurrences = append(n.occurrences, ID) }
func (n *artStruct) setHasSBOMs(ID string)         { n.hasSBOMs = append(n.hasSBOMs, ID) }
func (n *artStruct) setHasSLSAs(ID string)         { n.hasSLSAs = append(n.hasSLSAs, ID) }
func (n *artStruct) setVexLinks(ID string)         { n.vexLinks = append(n.vexLinks, ID) }
func (n *artStruct) setCertifyBadLinks(ID string)  { n.badLinks = append(n.badLinks, ID) }
func (n *artStruct) setCertifyGoodLinks(ID string) { n.goodLinks = append(n.goodLinks, ID) }
func (n *artStruct) setHasMetadataLinks(ID string) {
	n.hasMetadataLinks = append(n.hasMetadataLinks, ID)
}
func (n *artStruct) setPointOfContactLinks(ID string) {
	n.pointOfContactLinks = append(n.pointOfContactLinks, ID)
}

func (n *artStruct) Key() string {
	return strings.Join([]string{n.Algorithm, n.Digest}, ":")
}

func (n *artStruct) AddOcc(ctx context.Context, occ string, c *demoClient) error {
	n.Occurrences = append(n.Occurrences, occ)
	return setkv(ctx, artCol, n, c)
}

// func (c *demoClient) artifactSetOccurrences(ctx context.Context, aID string, oID string) error {
// 	a, err := byIDkv[*artStruct](ctx, aID, c)
// 	if err != nil {
// 		return err
// 	}
// 	a.Occurrences = append(a.Occurrences, oID)
// 	return c.artifactSet(ctx, a)
// }

// func (c *demoClient) artifactByKey(ctx context.Context, k string) (*artStruct, error) {
// 	strval, err := c.kv.Get(ctx, artCol, k)
// 	if err != nil {
// 		return nil, err
// 	}
// 	a := &artStruct{}
// 	if err = json.Unmarshal([]byte(strval), a); err != nil {
// 		return nil, err
// 	}
// 	return a, nil
// }

func (c *demoClient) artifactByInput(ctx context.Context, a *model.ArtifactInputSpec) (*artStruct, error) {
	inA := &artStruct{
		Algorithm: strings.ToLower(a.Algorithm),
		Digest:    strings.ToLower(a.Digest),
	}
	return byKeykv[*artStruct](ctx, artCol, inA.Key(), c)
}

// func (c *demoClient) artifactIDByInput(ctx context.Context, a *model.ArtifactInputSpec) (string, error) {
// 	art, err := c.artifactByInput(ctx, a)
// 	if err != nil {
// 		return "", err
// 	}
// 	return art.ThisID, nil
// }

// func (c *demoClient) artifactSet(ctx context.Context, a *artStruct) error {
// 	byteval, err := json.Marshal(a)
// 	if err != nil {
// 		return err
// 	}
// 	return c.kv.Set(ctx, artCol, artifactKey(a.Algorithm, a.Digest), string(byteval))
// }

func (c *demoClient) artifactModelByID(ctx context.Context, id string) (*model.Artifact, error) {
	a, err := byIDkv[*artStruct](ctx, id, c)
	if err != nil {
		return nil, err
	}
	return c.convArtifact(a), nil
}

// Ingest Artifacts

func (c *demoClient) IngestArtifacts(ctx context.Context, artifacts []*model.ArtifactInputSpec) ([]*model.Artifact, error) {
	var modelArtifacts []*model.Artifact
	for _, art := range artifacts {
		modelArt, err := c.IngestArtifact(ctx, art)
		if err != nil {
			return nil, gqlerror.Errorf("ingestArtifact failed with err: %v", err)
		}
		modelArtifacts = append(modelArtifacts, modelArt)
	}
	return modelArtifacts, nil
}

func (c *demoClient) IngestArtifact(ctx context.Context, artifact *model.ArtifactInputSpec) (*model.Artifact, error) {
	return c.ingestArtifact(ctx, artifact, true)
}

func (c *demoClient) ingestArtifact(ctx context.Context, artifact *model.ArtifactInputSpec, readOnly bool) (*model.Artifact, error) {
	algorithm := strings.ToLower(artifact.Algorithm)
	digest := strings.ToLower(artifact.Digest)

	inA := &artStruct{
		Algorithm: algorithm,
		Digest:    digest,
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	outA, err := byKeykv[*artStruct](ctx, artCol, inA.Key(), c)

	if err != nil {
		// FIXME, redis should catch key error and convert to these
		// if !errors.Is(err, kv.KeyError) && !errors.Is(err, kv.CollectionError) {
		// 	return nil, err
		// }
		// Got KeyError: not found, so do insert
		if readOnly {
			c.m.RUnlock()
			a, err := c.ingestArtifact(ctx, artifact, false)
			c.m.RLock() // relock so that defer unlock does not panic
			return a, err
		}
		inA.ThisID = c.getNextID()
		if err := c.addToIndex(ctx, artCol, inA); err != nil {
			return nil, err
		}
		if setkv(ctx, artCol, inA, c); err != nil {
			return nil, err
		}
		outA = inA
	}

	return c.convArtifact(outA), nil
}

func (c *demoClient) artifactExact(ctx context.Context, artifactSpec *model.ArtifactSpec) (*artStruct, error) {
	algorithm := strings.ToLower(nilToEmpty(artifactSpec.Algorithm))
	digest := strings.ToLower(nilToEmpty(artifactSpec.Digest))

	// If ID is provided, try to look up, then check if algo and digest match.
	if artifactSpec.ID != nil {
		a, err := byIDkv[*artStruct](ctx, *artifactSpec.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by ID, ignore rest of fields in spec and return as a match
		return a, nil
	}

	// If algo and digest are provied, try to lookup
	if algorithm != "" && digest != "" {
		inA := &artStruct{
			Algorithm: algorithm,
			Digest:    digest,
		}
		if outA, err := byKeykv[*artStruct](ctx, artCol, inA.Key(), c); err != nil {
			return outA, nil
		}
	}
	return nil, nil
}

// Query Artifacts

func (c *demoClient) Artifacts(ctx context.Context, artifactSpec *model.ArtifactSpec) ([]*model.Artifact, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	a, err := c.artifactExact(ctx, artifactSpec)
	if err != nil {
		return nil, gqlerror.Errorf("Artifacts :: invalid spec %s", err)
	}
	if a != nil {
		return []*model.Artifact{c.convArtifact(a)}, nil
	}

	algorithm := strings.ToLower(nilToEmpty(artifactSpec.Algorithm))
	digest := strings.ToLower(nilToEmpty(artifactSpec.Digest))
	var rv []*model.Artifact
	artKeys, err := c.kv.Keys(ctx, artCol)
	if err != nil {
		return nil, err
	}
	for _, ak := range artKeys {
		a, err := byKeykv[*artStruct](ctx, artCol, ak, c)
		if err != nil {
			return nil, err
		}

		matchAlgorithm := false
		if algorithm == "" || algorithm == a.Algorithm {
			matchAlgorithm = true
		}

		matchDigest := false
		if digest == "" || digest == a.Digest {
			matchDigest = true
		}

		if matchDigest && matchAlgorithm {
			rv = append(rv, c.convArtifact(a))
		}
	}
	return rv, nil
}

func (c *demoClient) convArtifact(a *artStruct) *model.Artifact {
	return &model.Artifact{
		ID:        a.ThisID,
		Digest:    a.Digest,
		Algorithm: a.Algorithm,
	}
}

// Builds a model.Artifact to send as GraphQL response, starting from ID.
// The optional filter allows restricting output (on selection operations).
func (c *demoClient) buildArtifactResponse(ctx context.Context, ID string, filter *model.ArtifactSpec) (*model.Artifact, error) {
	if filter != nil && filter.ID != nil && *filter.ID != ID {
		return nil, nil
	}

	artNode, err := byIDkv[*artStruct](ctx, ID, c)
	if err != nil {
		return nil, fmt.Errorf("ID does not match expected node type for artifact, %w", err)
	}

	if filter != nil && noMatch(toLower(filter.Algorithm), artNode.Algorithm) {
		return nil, nil
	}
	if filter != nil && noMatch(toLower(filter.Digest), artNode.Digest) {
		return nil, nil
	}
	art := &model.Artifact{
		ID:        artNode.ThisID,
		Algorithm: artNode.Algorithm,
		Digest:    artNode.Digest,
	}

	return art, nil
}
