package internal

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy/pkg/types"
	"gopkg.in/yaml.v3"
)

type PolicyMatcher interface {
	IsNonEmpty() bool
	IsMatch(report types.Report, res types.Result, vuln types.DetectedVulnerability) bool
	String() string
}

func PolicyMatcherUnmarshalYAML(value *yaml.Node) (PolicyMatcher, error) {
	nonEmpty := []PolicyMatcher{}

	not := NotPolicyMatcher{}
	if err := value.Decode(&not); err != nil {
		return nil, err
	} else if not.IsNonEmpty() {
		nonEmpty = append(nonEmpty, &not)
	}

	and := AndPolicyMatcher{}
	if err := value.Decode(&and); err != nil {
		return nil, err
	} else if and.IsNonEmpty() {
		nonEmpty = append(nonEmpty, &and)
	}

	or := OrPolicyMatcher{}
	if err := value.Decode(&or); err != nil {
		return nil, err
	} else if or.IsNonEmpty() {
		nonEmpty = append(nonEmpty, &or)
	}

	id := IDPolicyMatcher{}
	if err := value.Decode(&id); err != nil {
		return nil, err
	} else if id.IsNonEmpty() {
		nonEmpty = append(nonEmpty, &id)
	}

	artifactNameShort := ArtifactNameShortPolicyMatcher{}
	if err := value.Decode(&artifactNameShort); err != nil {
		return nil, err
	} else if artifactNameShort.IsNonEmpty() {
		nonEmpty = append(nonEmpty, &artifactNameShort)
	}

	packageName := PackageNamePolicyMatcher{}
	if err := value.Decode(&packageName); err != nil {
		return nil, err
	} else if packageName.IsNonEmpty() {
		nonEmpty = append(nonEmpty, &packageName)
	}

	class := ClassPolicyMatcher{}
	if err := value.Decode(&class); err != nil {
		return nil, err
	} else if class.IsNonEmpty() {
		nonEmpty = append(nonEmpty, &class)
	}

	cvss := CVSSPolicyMatcher{}
	if err := value.Decode(&cvss); err != nil {
		return nil, err
	} else if cvss.IsNonEmpty() {
		nonEmpty = append(nonEmpty, &cvss)
	}

	if len(nonEmpty) == 1 {
		return nonEmpty[0], nil
	}

	str, err := yaml.Marshal(value)
	if err != nil {
		return nil, err
	}
	message := "no valid matcher definition found"
	if len(nonEmpty) > 1 {
		message = "multiple valid matcher definitions found"
	}
	return nil, fmt.Errorf("unable to unmarshall matcher `%s`: %s", strings.ReplaceAll(string(str), "\n", "\\n"), message)
}

var _ PolicyMatcher = (*NotPolicyMatcher)(nil)

type NotPolicyMatcher struct {
	Not PolicyMatcher `yaml:"not"`
}

func (p *NotPolicyMatcher) IsNonEmpty() bool {
	return p.Not != nil && p.Not.IsNonEmpty()
}

func (p *NotPolicyMatcher) IsMatch(report types.Report, res types.Result, vuln types.DetectedVulnerability) bool {
	return p.Not == nil || !p.Not.IsMatch(report, res, vuln)
}

func (p *NotPolicyMatcher) String() string {
	if p.Not == nil {
		return "not(<nil>)"
	}
	return fmt.Sprintf("not(%s)", p.Not.String())
}

func (p *NotPolicyMatcher) UnmarshalYAML(value *yaml.Node) error {
	var raw map[string](yaml.Node)
	err := value.Decode(&raw)
	if err != nil {
		return nil
	}
	valueNot, ok := raw["not"]
	if !ok {
		return nil
	}
	not, err := PolicyMatcherUnmarshalYAML(&valueNot)
	if err != nil {
		return err
	}
	p.Not = not
	return nil
}

var _ PolicyMatcher = (*AndPolicyMatcher)(nil)

type AndPolicyMatcher struct {
	And []PolicyMatcher `yaml:"and"`
}

func (p *AndPolicyMatcher) IsNonEmpty() bool {
	return len(p.And) > 0
}

func (p *AndPolicyMatcher) IsMatch(report types.Report, res types.Result, vuln types.DetectedVulnerability) bool {
	for _, i := range p.And {
		if !i.IsMatch(report, res, vuln) {
			return false
		}
	}
	return true
}

func (p *AndPolicyMatcher) String() string {
	inners := []string{}
	for _, inner := range p.And {
		inners = append(inners, inner.String())
	}
	return fmt.Sprintf("and(%s)", strings.Join(inners, ","))
}

func (p *AndPolicyMatcher) UnmarshalYAML(value *yaml.Node) error {
	var raw map[string]([]yaml.Node)
	err := value.Decode(&raw)
	if err != nil {
		return nil
	}
	valuesAnd, ok := raw["and"]
	if !ok {
		return nil
	}
	for _, valueAnd := range valuesAnd {
		and, err := PolicyMatcherUnmarshalYAML(&valueAnd)
		if err != nil {
			return err
		}
		p.And = append(p.And, and)
	}
	return nil
}

var _ PolicyMatcher = (*OrPolicyMatcher)(nil)

type OrPolicyMatcher struct {
	Or []PolicyMatcher `yaml:"or"`
}

func (p *OrPolicyMatcher) IsNonEmpty() bool {
	return len(p.Or) > 0
}

func (p *OrPolicyMatcher) IsMatch(report types.Report, res types.Result, vuln types.DetectedVulnerability) bool {
	for _, i := range p.Or {
		if i.IsMatch(report, res, vuln) {
			return true
		}
	}
	return false
}

func (p *OrPolicyMatcher) String() string {
	inners := []string{}
	for _, inner := range p.Or {
		inners = append(inners, inner.String())
	}
	return fmt.Sprintf("or(%s)", strings.Join(inners, ","))
}

func (p *OrPolicyMatcher) UnmarshalYAML(value *yaml.Node) error {
	var raw map[string]([]yaml.Node)
	err := value.Decode(&raw)
	if err != nil {
		return nil
	}
	valuesOr, ok := raw["or"]
	if !ok {
		return nil
	}
	for _, valueOr := range valuesOr {
		or, err := PolicyMatcherUnmarshalYAML(&valueOr)
		if err != nil {
			return err
		}
		p.Or = append(p.Or, or)
	}
	return nil
}

var _ PolicyMatcher = (*IDPolicyMatcher)(nil)

type IDPolicyMatcher struct {
	ID StringArray `yaml:"id"`
}

func (p *IDPolicyMatcher) IsNonEmpty() bool {
	return len(p.ID) > 0
}

func (p *IDPolicyMatcher) IsMatch(report types.Report, res types.Result, vuln types.DetectedVulnerability) bool {
	for _, id := range p.ID {
		if id == vuln.VulnerabilityID {
			return true
		}
	}
	return false
}

func (p *IDPolicyMatcher) String() string {
	inners := []string{}
	for _, inner := range p.ID {
		inners = append(inners, inner)
	}
	return fmt.Sprintf("id(%s)", strings.Join(inners, ","))
}

var _ PolicyMatcher = (*ArtifactNameShortPolicyMatcher)(nil)

type ArtifactNameShortPolicyMatcher struct {
	ArtifactNameShort StringArray `yaml:"artifactNameShort"`
}

func (p *ArtifactNameShortPolicyMatcher) IsNonEmpty() bool {
	return len(p.ArtifactNameShort) > 0
}

func (p *ArtifactNameShortPolicyMatcher) IsMatch(report types.Report, res types.Result, vuln types.DetectedVulnerability) bool {
	for _, n := range p.ArtifactNameShort {
		if n == strings.SplitN(report.ArtifactName, ":", 2)[0] {
			return true
		}
	}
	return false
}

func (p *ArtifactNameShortPolicyMatcher) String() string {
	inners := []string{}
	for _, inner := range p.ArtifactNameShort {
		inners = append(inners, inner)
	}
	return fmt.Sprintf("artifactNameShort(%s)", strings.Join(inners, ","))
}

var _ PolicyMatcher = (*PackageNamePolicyMatcher)(nil)

type PackageNamePolicyMatcher struct {
	PackageName StringArray `yaml:"packageName"`
}

func (p *PackageNamePolicyMatcher) IsNonEmpty() bool {
	return len(p.PackageName) > 0
}

func (p *PackageNamePolicyMatcher) IsMatch(report types.Report, res types.Result, vuln types.DetectedVulnerability) bool {
	for _, n := range p.PackageName {
		if n == vuln.PkgName {
			return true
		}
	}
	return false
}

func (p *PackageNamePolicyMatcher) String() string {
	inners := []string{}
	for _, inner := range p.PackageName {
		inners = append(inners, inner)
	}
	return fmt.Sprintf("packageName(%s)", strings.Join(inners, ","))
}

var _ PolicyMatcher = (*ClassPolicyMatcher)(nil)

type ClassPolicyMatcher struct {
	Class StringArray `yaml:"class"`
}

func (p *ClassPolicyMatcher) IsNonEmpty() bool {
	return len(p.Class) > 0
}

func (p *ClassPolicyMatcher) IsMatch(report types.Report, res types.Result, vuln types.DetectedVulnerability) bool {
	for _, n := range p.Class {
		if n == string(res.Class) {
			return true
		}
	}
	return false
}

func (p *ClassPolicyMatcher) String() string {
	inners := []string{}
	for _, inner := range p.Class {
		inners = append(inners, inner)
	}
	return fmt.Sprintf("class(%s)", strings.Join(inners, ","))
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

func (p *CVSSPolicyMatcher) IsNonEmpty() bool {
	return p.CVSS.ScoreLowerThan > 0 ||
		len(p.CVSS.AV) > 0 ||
		len(p.CVSS.AC) > 0 ||
		len(p.CVSS.PR) > 0 ||
		len(p.CVSS.UI) > 0 ||
		len(p.CVSS.S) > 0 ||
		len(p.CVSS.C) > 0 ||
		len(p.CVSS.I) > 0 ||
		len(p.CVSS.A) > 0
}

func (p *CVSSPolicyMatcher) IsMatch(report types.Report, res types.Result, vuln types.DetectedVulnerability) bool {
	_, cvssScore, cvssBaseMetric := FindVulnerabilityCVSSV3(vuln)

	if p.CVSS.ScoreLowerThan != 0 && cvssScore >= p.CVSS.ScoreLowerThan {
		return false
	}
	if len(p.CVSS.AV) > 0 && (cvssBaseMetric == nil || !StringsContain(p.CVSS.AV, cvssBaseMetric.AV.String())) {
		return false
	}
	if len(p.CVSS.AC) > 0 && (cvssBaseMetric == nil || !StringsContain(p.CVSS.AC, cvssBaseMetric.AC.String())) {
		return false
	}
	if len(p.CVSS.PR) > 0 && (cvssBaseMetric == nil || !StringsContain(p.CVSS.PR, cvssBaseMetric.PR.String())) {
		return false
	}
	if len(p.CVSS.UI) > 0 && (cvssBaseMetric == nil || !StringsContain(p.CVSS.UI, cvssBaseMetric.UI.String())) {
		return false
	}
	if len(p.CVSS.S) > 0 && (cvssBaseMetric == nil || !StringsContain(p.CVSS.S, cvssBaseMetric.S.String())) {
		return false
	}
	if len(p.CVSS.C) > 0 && (cvssBaseMetric == nil || !StringsContain(p.CVSS.C, cvssBaseMetric.C.String())) {
		return false
	}
	if len(p.CVSS.I) > 0 && (cvssBaseMetric == nil || !StringsContain(p.CVSS.I, cvssBaseMetric.I.String())) {
		return false
	}
	if len(p.CVSS.A) > 0 && (cvssBaseMetric == nil || !StringsContain(p.CVSS.A, cvssBaseMetric.A.String())) {
		return false
	}

	return true
}

func (p *CVSSPolicyMatcher) String() string {
	inners := []string{}
	if p.CVSS.ScoreLowerThan > 0 {
		inners = append(inners, fmt.Sprintf("score(<=%.1f)", p.CVSS.ScoreLowerThan))
	}
	if len(p.CVSS.AV) > 0 {
		inners = append(inners, fmt.Sprintf("av(%s)", strings.Join(p.CVSS.AV, ",")))
	}
	if len(p.CVSS.AC) > 0 {
		inners = append(inners, fmt.Sprintf("ac(%s)", strings.Join(p.CVSS.AC, ",")))
	}
	if len(p.CVSS.PR) > 0 {
		inners = append(inners, fmt.Sprintf("pr(%s)", strings.Join(p.CVSS.PR, ",")))
	}
	if len(p.CVSS.UI) > 0 {
		inners = append(inners, fmt.Sprintf("ui(%s)", strings.Join(p.CVSS.UI, ",")))
	}
	if len(p.CVSS.S) > 0 {
		inners = append(inners, fmt.Sprintf("s(%s)", strings.Join(p.CVSS.S, ",")))
	}
	if len(p.CVSS.C) > 0 {
		inners = append(inners, fmt.Sprintf("c(%s)", strings.Join(p.CVSS.C, ",")))
	}
	if len(p.CVSS.I) > 0 {
		inners = append(inners, fmt.Sprintf("i(%s)", strings.Join(p.CVSS.I, ",")))
	}
	if len(p.CVSS.A) > 0 {
		inners = append(inners, fmt.Sprintf("a(%s)", strings.Join(p.CVSS.A, ",")))
	}
	return fmt.Sprintf("cvss(%s)", strings.Join(inners, ","))
}
