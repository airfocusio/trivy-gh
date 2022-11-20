package internal

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/goark/go-cvss/v3/metric"
	"gopkg.in/yaml.v3"
)

type PolicyMatcher interface {
	IsMatch(report types.Report, res types.Result, vuln types.DetectedVulnerability) bool
}

func PolicyMatcherUnmarshalYAML(value *yaml.Node) (PolicyMatcher, error) {
	id := IDPolicyMatcher{}
	if err := id.UnmarshalYAML(value); err == nil {
		return &id, nil
	}

	artifactNameShort := ArtifactNameShortPolicyMatcher{}
	if err := artifactNameShort.UnmarshalYAML(value); err == nil {
		return &artifactNameShort, nil
	}

	packageName := PackageNamePolicyMatcher{}
	if err := packageName.UnmarshalYAML(value); err == nil {
		return &packageName, nil
	}

	cvss := CVSSPolicyMatcher{}
	if err := cvss.UnmarshalYAML(value); err == nil {
		return &cvss, nil
	}

	return nil, fmt.Errorf("matcher invalid")
}

var _ PolicyMatcher = (*YesPolicyMatcher)(nil)

type YesPolicyMatcher struct{}

func (p *YesPolicyMatcher) IsMatch(report types.Report, res types.Result, vuln types.DetectedVulnerability) bool {
	return true
}

var _ PolicyMatcher = (*NoPolicyMatcher)(nil)

type NoPolicyMatcher struct{}

func (p *NoPolicyMatcher) IsMatch(report types.Report, res types.Result, vuln types.DetectedVulnerability) bool {
	return false
}

var _ PolicyMatcher = (*AndPolicyMatcher)(nil)

type AndPolicyMatcher struct {
	Inner []PolicyMatcher
}

func (p *AndPolicyMatcher) IsMatch(report types.Report, res types.Result, vuln types.DetectedVulnerability) bool {
	for _, i := range p.Inner {
		if !i.IsMatch(report, res, vuln) {
			return false
		}
	}
	return true
}

var _ PolicyMatcher = (*OrPolicyMatcher)(nil)

type OrPolicyMatcher struct {
	Inner []PolicyMatcher
}

func (p *OrPolicyMatcher) IsMatch(report types.Report, res types.Result, vuln types.DetectedVulnerability) bool {
	for _, i := range p.Inner {
		if i.IsMatch(report, res, vuln) {
			return true
		}
	}
	return false
}

var _ PolicyMatcher = (*IDPolicyMatcher)(nil)

type IDPolicyMatcher struct {
	ID []string `yaml:"id"`
}

func (p *IDPolicyMatcher) IsMatch(report types.Report, res types.Result, vuln types.DetectedVulnerability) bool {
	for _, id := range p.ID {
		if id == vuln.VulnerabilityID {
			return true
		}
	}
	return false
}

func (c *IDPolicyMatcher) UnmarshalYAML(value *yaml.Node) error {
	type IDPolicyMatcher2 IDPolicyMatcher
	err := value.Decode((*IDPolicyMatcher2)(c))
	if err != nil {
		return err
	}
	if len(c.ID) == 0 {
		return fmt.Errorf("not a IDPolicyMatcher")
	}
	return nil
}

var _ PolicyMatcher = (*ArtifactNameShortPolicyMatcher)(nil)

type ArtifactNameShortPolicyMatcher struct {
	ArtifactNameShort []string `yaml:"artifactNameShort"`
}

func (p *ArtifactNameShortPolicyMatcher) IsMatch(report types.Report, res types.Result, vuln types.DetectedVulnerability) bool {
	for _, n := range p.ArtifactNameShort {
		if n == strings.SplitN(report.ArtifactName, ":", 2)[0] {
			return true
		}
	}
	return false
}

func (c *ArtifactNameShortPolicyMatcher) UnmarshalYAML(value *yaml.Node) error {
	type ArtifactNameShortPolicyMatcher2 ArtifactNameShortPolicyMatcher
	err := value.Decode((*ArtifactNameShortPolicyMatcher2)(c))
	if err != nil {
		return err
	}
	if len(c.ArtifactNameShort) == 0 {
		return fmt.Errorf("not a ArtifactNameShortPolicyMatcher")
	}
	return nil
}

var _ PolicyMatcher = (*PackageNamePolicyMatcher)(nil)

type PackageNamePolicyMatcher struct {
	PackageName []string `yaml:"packageName"`
}

func (p *PackageNamePolicyMatcher) IsMatch(report types.Report, res types.Result, vuln types.DetectedVulnerability) bool {
	for _, n := range p.PackageName {
		if n == vuln.PkgName {
			return true
		}
	}
	return false
}

func (c *PackageNamePolicyMatcher) UnmarshalYAML(value *yaml.Node) error {
	type PackageNamePolicyMatcher2 PackageNamePolicyMatcher
	err := value.Decode((*PackageNamePolicyMatcher2)(c))
	if err != nil {
		return err
	}
	if len(c.PackageName) == 0 {
		return fmt.Errorf("not a PackageNamePolicyMatcher")
	}
	return nil
}

type CVSSPolicyMatcher struct {
	CVSS CVSSPolicyMatcherCVSS `yaml:"cvss"`
}

type CVSSPolicyMatcherCVSS struct {
	ScoreLowerThan float64  `yaml:"scoreLowerThan"`
	AV             []string `yaml:"av"`
	AC             []string `yaml:"ac"`
	PR             []string `yaml:"pr"`
	UI             []string `yaml:"ui"`
	S              []string `yaml:"s"`
	C              []string `yaml:"c"`
	I              []string `yaml:"i"`
	A              []string `yaml:"a"`
}

func (p *CVSSPolicyMatcher) IsMatch(report types.Report, res types.Result, vuln types.DetectedVulnerability) bool {
	isMatch := true

	cvssVector, cvssScore := FindVulnerabilityCVSSV3(vuln)
	var cvssBaseMetric *metric.Base
	if cvssVector != "" {
		bm, err := metric.NewBase().Decode(cvssVector)
		if err == nil && bm.Ver != metric.VUnknown {
			cvssBaseMetric = bm
		}
	}

	if p.CVSS.ScoreLowerThan != 0 && cvssScore >= p.CVSS.ScoreLowerThan {
		isMatch = false
	}
	if len(p.CVSS.AV) > 0 && (cvssBaseMetric == nil || !StringsContain(p.CVSS.AV, cvssBaseMetric.AV.String())) {
		isMatch = false
	}
	if len(p.CVSS.AC) > 0 && (cvssBaseMetric == nil || !StringsContain(p.CVSS.AC, cvssBaseMetric.AC.String())) {
		isMatch = false
	}
	if len(p.CVSS.PR) > 0 && (cvssBaseMetric == nil || !StringsContain(p.CVSS.PR, cvssBaseMetric.PR.String())) {
		isMatch = false
	}
	if len(p.CVSS.S) > 0 && (cvssBaseMetric == nil || !StringsContain(p.CVSS.S, cvssBaseMetric.S.String())) {
		isMatch = false
	}
	if len(p.CVSS.C) > 0 && (cvssBaseMetric == nil || !StringsContain(p.CVSS.C, cvssBaseMetric.C.String())) {
		isMatch = false
	}
	if len(p.CVSS.I) > 0 && (cvssBaseMetric == nil || !StringsContain(p.CVSS.I, cvssBaseMetric.I.String())) {
		isMatch = false
	}
	if len(p.CVSS.A) > 0 && (cvssBaseMetric == nil || !StringsContain(p.CVSS.A, cvssBaseMetric.A.String())) {
		isMatch = false
	}

	return isMatch
}

func (c *CVSSPolicyMatcher) UnmarshalYAML(value *yaml.Node) error {
	type CVSSPolicyMatcher2 CVSSPolicyMatcher
	err := value.Decode((*CVSSPolicyMatcher2)(c))
	if err != nil {
		return err
	}
	if c.CVSS.ScoreLowerThan == 0 && len(c.CVSS.AV) == 0 && len(c.CVSS.AC) == 0 && len(c.CVSS.PR) == 0 && len(c.CVSS.UI) == 0 && len(c.CVSS.S) == 0 && len(c.CVSS.C) == 0 && len(c.CVSS.I) == 0 && len(c.CVSS.A) == 0 {
		return fmt.Errorf("not a CVSSPolicyMatcher")
	}
	return nil
}
