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
	"slices"
	"time"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// Internal certifyLegal

type (
	certifyLegalList   []*certifyLegalStruct
	certifyLegalStruct struct {
		id                 string
		pkg                string
		source             string
		declaredLicense    string
		declaredLicenses   []string
		discoveredLicense  string
		discoveredLicenses []string
		attribution        string
		justification      string
		timeScanned        time.Time
		origin             string
		collector          string
	}
)

func (n *certifyLegalStruct) ID() string  { return n.id }
func (n *certifyLegalStruct) Key() string { return n.id }

func (n *certifyLegalStruct) Neighbors(allowedEdges edgeMap) []string {
	out := make([]string, 0, 2)
	if n.pkg != "" && allowedEdges[model.EdgeCertifyLegalPackage] {
		out = append(out, n.pkg)
	}
	if n.source != "" && allowedEdges[model.EdgeCertifyLegalSource] {
		out = append(out, n.source)
	}
	if allowedEdges[model.EdgeCertifyLegalLicense] {
		out = append(out, n.declaredLicenses...)
		out = append(out, n.discoveredLicenses...)
	}
	return out
}

func (n *certifyLegalStruct) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.convLegal(ctx, n)
}

func (c *demoClient) IngestCertifyLegals(ctx context.Context, subjects model.PackageOrSourceInputs, declaredLicensesList [][]*model.LicenseInputSpec, discoveredLicensesList [][]*model.LicenseInputSpec, certifyLegals []*model.CertifyLegalInputSpec) ([]*model.CertifyLegal, error) {
	var rv []*model.CertifyLegal

	for i, v := range certifyLegals {
		var l *model.CertifyLegal
		var err error
		if len(subjects.Packages) > 0 {
			subject := model.PackageOrSourceInput{Package: subjects.Packages[i]}
			l, err = c.IngestCertifyLegal(ctx, subject, declaredLicensesList[i], discoveredLicensesList[i], v)
			if err != nil {
				return nil, gqlerror.Errorf("IngestCertifyLegals failed with err: %v", err)
			}
		} else {
			subject := model.PackageOrSourceInput{Source: subjects.Sources[i]}
			l, err = c.IngestCertifyLegal(ctx, subject, declaredLicensesList[i], discoveredLicensesList[i], v)
			if err != nil {
				return nil, gqlerror.Errorf("IngestCertifyLegals failed with err: %v", err)
			}
		}
		rv = append(rv, l)
	}
	return rv, nil
}

func (c *demoClient) IngestCertifyLegal(ctx context.Context, subject model.PackageOrSourceInput, declaredLicenses []*model.LicenseInputSpec, discoveredLicenses []*model.LicenseInputSpec, certifyLegal *model.CertifyLegalInputSpec) (*model.CertifyLegal, error) {
	return c.ingestCertifyLegal(ctx, subject, declaredLicenses, discoveredLicenses, certifyLegal, true)
}

func (c *demoClient) ingestCertifyLegal(ctx context.Context, subject model.PackageOrSourceInput, declaredLicenses []*model.LicenseInputSpec, discoveredLicenses []*model.LicenseInputSpec, certifyLegal *model.CertifyLegalInputSpec, readOnly bool) (*model.CertifyLegal, error) {
	funcName := "IngestCertifyLegal"

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	var dec []string
	for _, lis := range declaredLicenses {
		l, ok := c.licenses[licenseKey(lis.Name, lis.ListVersion)]
		if !ok {
			return nil, gqlerror.Errorf("%v :: License not found %q", funcName, licenseKey(lis.Name, lis.ListVersion))
		}
		dec = append(dec, l.id)
	}
	slices.Sort(dec)
	var dis []string
	for _, lis := range discoveredLicenses {
		l, ok := c.licenses[licenseKey(lis.Name, lis.ListVersion)]
		if !ok {
			return nil, gqlerror.Errorf("%v :: License not found %q", funcName, licenseKey(lis.Name, lis.ListVersion))
		}
		dis = append(dis, l.id)
	}
	slices.Sort(dis)

	var backedgeSearch []string
	var packageID string
	var pkg *pkgVersion
	if subject.Package != nil {
		var err error
		pkg, err = c.getPackageVerFromInput(ctx, *subject.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		backedgeSearch = pkg.CertifyLegals
	}

	var sourceID string
	var src *srcNameNode
	if subject.Source != nil {
		sid, err := getSourceIDFromInput(c, *subject.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		sourceID = sid
		src, err = byID[*srcNameNode](sourceID, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		backedgeSearch = src.certifyLegals
	}

	for _, id := range backedgeSearch {
		cl, err := byID[*certifyLegalStruct](id, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		if cl.pkg == packageID &&
			cl.source == sourceID &&
			cl.declaredLicense == certifyLegal.DeclaredLicense &&
			slices.Equal(cl.declaredLicenses, dec) &&
			cl.discoveredLicense == certifyLegal.DiscoveredLicense &&
			slices.Equal(cl.discoveredLicenses, dis) &&
			cl.attribution == certifyLegal.Attribution &&
			cl.timeScanned.Equal(certifyLegal.TimeScanned) &&
			cl.justification == certifyLegal.Justification &&
			cl.origin == certifyLegal.Origin &&
			cl.collector == certifyLegal.Collector {
			return c.convLegal(ctx, cl)
		}
	}
	if readOnly {
		c.m.RUnlock()
		o, err := c.ingestCertifyLegal(ctx, subject, declaredLicenses, discoveredLicenses, certifyLegal, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return o, err
	}
	cl := &certifyLegalStruct{
		id:                 c.getNextID(),
		pkg:                packageID,
		source:             sourceID,
		declaredLicense:    certifyLegal.DeclaredLicense,
		declaredLicenses:   dec,
		discoveredLicense:  certifyLegal.DiscoveredLicense,
		discoveredLicenses: dis,
		attribution:        certifyLegal.Attribution,
		timeScanned:        certifyLegal.TimeScanned,
		justification:      certifyLegal.Justification,
		origin:             certifyLegal.Origin,
		collector:          certifyLegal.Collector,
	}
	c.index[cl.id] = cl
	if packageID != "" {
		pkg.setCertifyLegals(cl.id)
	} else {
		src.setCertifyLegals(cl.id)
	}
	for _, lid := range dec {
		l, err := byID[*licStruct](lid, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		l.setCertifyLegals(cl.id)
	}
	for _, lid := range dis {
		l, err := byID[*licStruct](lid, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		l.setCertifyLegals(cl.id)
	}
	c.certifyLegals = append(c.certifyLegals, cl)

	return c.convLegal(ctx, cl)
}

func (c *demoClient) convLegal(ctx context.Context, in *certifyLegalStruct) (*model.CertifyLegal, error) {
	cl := &model.CertifyLegal{
		ID:                in.id,
		DeclaredLicense:   in.declaredLicense,
		DiscoveredLicense: in.discoveredLicense,
		Attribution:       in.attribution,
		Justification:     in.justification,
		TimeScanned:       in.timeScanned,
		Origin:            in.origin,
		Collector:         in.collector,
	}
	for _, lid := range in.declaredLicenses {
		l, err := byID[*licStruct](lid, c)
		if err != nil {
			return nil, err
		}
		cl.DeclaredLicenses = append(cl.DeclaredLicenses, c.convLicense(l))
	}
	for _, lid := range in.discoveredLicenses {
		l, err := byID[*licStruct](lid, c)
		if err != nil {
			return nil, err
		}
		cl.DiscoveredLicenses = append(cl.DiscoveredLicenses, c.convLicense(l))
	}
	if in.pkg != "" {
		p, err := c.buildPackageResponse(ctx, in.pkg, nil)
		if err != nil {
			return nil, err
		}
		cl.Subject = p
	} else {
		s, err := c.buildSourceResponse(in.source, nil)
		if err != nil {
			return nil, err
		}
		cl.Subject = s
	}
	return cl, nil
}

func (c *demoClient) CertifyLegal(ctx context.Context, filter *model.CertifyLegalSpec) ([]*model.CertifyLegal, error) {
	funcName := "CertifyLegal"

	c.m.RLock()
	defer c.m.RUnlock()

	if filter != nil && filter.ID != nil {
		link, err := byID[*certifyLegalStruct](*filter.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		o, err := c.convLegal(ctx, link)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.CertifyLegal{o}, nil
	}

	var search []string
	foundOne := false
	if filter != nil && filter.Subject != nil && filter.Subject.Package != nil {
		pkgs, err := c.findPackageVersion(ctx, filter.Subject.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		foundOne = len(pkgs) > 0
		for _, pkg := range pkgs {
			search = append(search, pkg.CertifyLegals...)
		}
	}
	if !foundOne && filter != nil && filter.Subject != nil && filter.Subject.Source != nil {
		exactSource, err := c.exactSource(filter.Subject.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactSource != nil {
			search = append(search, exactSource.certifyLegals...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil {
		for _, lSpec := range filter.DeclaredLicenses {
			exactLicense, err := c.licenseExact(lSpec)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			if exactLicense != nil {
				search = append(search, exactLicense.certifyLegals...)
				foundOne = true
				break
			}
		}
	}
	if !foundOne && filter != nil {
		for _, lSpec := range filter.DiscoveredLicenses {
			exactLicense, err := c.licenseExact(lSpec)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			if exactLicense != nil {
				search = append(search, exactLicense.certifyLegals...)
				foundOne = true
				break
			}
		}
	}

	var out []*model.CertifyLegal
	if foundOne {
		for _, id := range search {
			link, err := byID[*certifyLegalStruct](id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addLegalIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		for _, link := range c.certifyLegals {
			var err error
			out, err = c.addLegalIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}
	return out, nil
}

func (c *demoClient) addLegalIfMatch(ctx context.Context, out []*model.CertifyLegal,
	filter *model.CertifyLegalSpec, link *certifyLegalStruct) (
	[]*model.CertifyLegal, error,
) {
	if noMatch(filter.DeclaredLicense, link.declaredLicense) ||
		noMatch(filter.DiscoveredLicense, link.discoveredLicense) ||
		noMatch(filter.Attribution, link.attribution) ||
		noMatch(filter.Justification, link.justification) ||
		noMatch(filter.Origin, link.origin) ||
		noMatch(filter.Collector, link.collector) ||
		(filter.TimeScanned != nil && !link.timeScanned.Equal(*filter.TimeScanned)) ||
		!c.matchLicenses(filter.DeclaredLicenses, link.declaredLicenses) ||
		!c.matchLicenses(filter.DiscoveredLicenses, link.discoveredLicenses) {
		return out, nil
	}
	if filter.Subject != nil {
		if filter.Subject.Package != nil {
			if link.pkg == "" {
				return out, nil
			}
			p, err := c.buildPackageResponse(ctx, link.pkg, filter.Subject.Package)
			if err != nil {
				return nil, err
			}
			if p == nil {
				return out, nil
			}
		} else if filter.Subject.Source != nil {
			if link.source == "" {
				return out, nil
			}
			s, err := c.buildSourceResponse(link.source, filter.Subject.Source)
			if err != nil {
				return nil, err
			}
			if s == nil {
				return out, nil
			}
		}
	}
	o, err := c.convLegal(ctx, link)
	if err != nil {
		return nil, err
	}
	return append(out, o), nil
}

func (c *demoClient) matchLicenses(filter []*model.LicenseSpec, value []string) bool {
	val := slices.Clone(value)
	var matchID []string
	var matchPartial []*model.LicenseSpec
	for _, aSpec := range filter {
		if aSpec == nil {
			continue
		}
		a, _ := c.licenseExact(aSpec)
		// drop error here if ID is bad
		if a != nil {
			matchID = append(matchID, a.id)
		} else {
			matchPartial = append(matchPartial, aSpec)
		}
	}
	for _, m := range matchID {
		if !slices.Contains(val, m) {
			return false
		}
		val = slices.Delete(val, slices.Index(val, m), slices.Index(val, m)+1)
	}
	for _, m := range matchPartial {
		match := false
		remove := -1
		for i, v := range val {
			a, err := byID[*licStruct](v, c)
			if err != nil {
				return false
			}
			if (m.Name == nil || *m.Name == a.name) &&
				(m.ListVersion == nil || *m.ListVersion == a.listVersion) &&
				(m.Inline == nil || *m.Inline == a.inline) {
				match = true
				remove = i
				break
			}
		}
		if !match {
			return false
		}
		val = slices.Delete(val, remove, remove+1)
	}
	return true
}