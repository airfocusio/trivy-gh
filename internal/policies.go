package internal

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy/pkg/types"
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

	class := ClassPolicyMatcher{}
	if err := class.UnmarshalYAML(value); err == nil {
		return &class, nil
	}

	cvss := CVSSPolicyMatcher{}
	if err := cvss.UnmarshalYAML(value); err == nil {
		return &cvss, nil
	}

	str, err := yaml.Marshal(value)
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("unable to unmarshall matcher `%s`", strings.ReplaceAll(string(str), "\n", "\\n"))
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
	ID StringArray `yaml:"id"`
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
	ArtifactNameShort StringArray `yaml:"artifactNameShort"`
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
	PackageName StringArray `yaml:"packageName"`
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

var _ PolicyMatcher = (*ClassPolicyMatcher)(nil)

type ClassPolicyMatcher struct {
	Class StringArray `yaml:"class"`
}

func (p *ClassPolicyMatcher) IsMatch(report types.Report, res types.Result, vuln types.DetectedVulnerability) bool {
	for _, n := range p.Class {
		if n == string(res.Class) {
			return true
		}
	}
	return false
}

func (c *ClassPolicyMatcher) UnmarshalYAML(value *yaml.Node) error {
	type ClassPolicyMatcher2 ClassPolicyMatcher
	err := value.Decode((*ClassPolicyMatcher2)(c))
	if err != nil {
		return err
	}
	if len(c.Class) == 0 {
		return fmt.Errorf("not a ClassPolicyMatcher")
	}
	return nil
}

type CVSSPolicyMatcher struct {
	CVSS CVSSPolicyMatcherCVSS `yaml:"cvss"`
}

type CVSSPolicyMatcherCVSS struct {
	ScoreLowerThan float64     `yaml:"scoreLowerThan"`
	AV             StringArray `yaml:"av"`
	AC             StringArray `yaml:"ac"`
	PR             StringArray `yaml:"pr"`
	UI             StringArray `yaml:"ui"`
	S              StringArray `yaml:"s"`
	C              StringArray `yaml:"c"`
	I              StringArray `yaml:"i"`
	A              StringArray `yaml:"a"`
}

func (p *CVSSPolicyMatcher) IsMatch(report types.Report, res types.Result, vuln types.DetectedVulnerability) bool {
	_, cvssScore, cvssBaseMetric := FindVulnerabilityCVSSV3(vuln)

	isMatch := true
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
