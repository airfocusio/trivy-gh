package internal

import (
	"testing"

	trivydbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
)

var _ PolicyMatcher = (*YesPolicyMatcher)(nil)

type YesPolicyMatcher struct{}

func (p *YesPolicyMatcher) IsNonEmpty() bool {
	return true
}

func (p *YesPolicyMatcher) IsMatch(report types.Report, res types.Result, vuln types.DetectedVulnerability) bool {
	return true
}

func (p *YesPolicyMatcher) String() string {
	return "yes"
}

var _ PolicyMatcher = (*NoPolicyMatcher)(nil)

type NoPolicyMatcher struct{}

func (p *NoPolicyMatcher) IsNonEmpty() bool {
	return true
}

func (p *NoPolicyMatcher) IsMatch(report types.Report, res types.Result, vuln types.DetectedVulnerability) bool {
	return false
}

func (p *NoPolicyMatcher) String() string {
	return "no"
}

func TestPolicyMatcherString(t *testing.T) {
	p := AndPolicyMatcher{
		And: []PolicyMatcher{
			&NotPolicyMatcher{
				Not: &IDPolicyMatcher{
					ID: []string{"CVE-0"},
				},
			},
			&PackageNamePolicyMatcher{
				PackageName: []string{"dpkg", "apit"},
			},
			&CVSSPolicyMatcher{
				CVSS: CVSSPolicyMatcherCVSS{
					ScoreLowerThan: 5,
					AV:             []string{"N", "A"},
					AC:             []string{"H"},
					PR:             []string{"H"},
					UI:             []string{"H"},
					S:              []string{"H"},
					C:              []string{"H"},
					I:              []string{"H"},
					A:              []string{"H"},
				},
			},
		},
	}
	assert.Equal(t, "and(not(id(CVE-0)),packageName(dpkg,apit),cvss(score(<=5.0),av(N,A),ac(H),pr(H),ui(H),s(H),c(H),i(H),a(H)))", p.String())
}

func TestAndPolicyMatcher(t *testing.T) {
	p1 := AndPolicyMatcher{}
	assert.Equal(t, true, p1.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{}))
	p2 := AndPolicyMatcher{And: []PolicyMatcher{&YesPolicyMatcher{}}}
	assert.Equal(t, true, p2.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{}))
	p3 := AndPolicyMatcher{And: []PolicyMatcher{&YesPolicyMatcher{}, &YesPolicyMatcher{}}}
	assert.Equal(t, true, p3.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{}))
	p4 := AndPolicyMatcher{And: []PolicyMatcher{&NoPolicyMatcher{}}}
	assert.Equal(t, false, p4.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{}))
	p5 := AndPolicyMatcher{And: []PolicyMatcher{&YesPolicyMatcher{}, &NoPolicyMatcher{}}}
	assert.Equal(t, false, p5.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{}))
}

func TestOrPolicyMatcher(t *testing.T) {
	p1 := OrPolicyMatcher{}
	assert.Equal(t, false, p1.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{}))
	p2 := OrPolicyMatcher{Or: []PolicyMatcher{&YesPolicyMatcher{}}}
	assert.Equal(t, true, p2.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{}))
	p3 := OrPolicyMatcher{Or: []PolicyMatcher{&YesPolicyMatcher{}, &YesPolicyMatcher{}}}
	assert.Equal(t, true, p3.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{}))
	p4 := OrPolicyMatcher{Or: []PolicyMatcher{&NoPolicyMatcher{}}}
	assert.Equal(t, false, p4.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{}))
	p5 := OrPolicyMatcher{Or: []PolicyMatcher{&YesPolicyMatcher{}, &NoPolicyMatcher{}}}
	assert.Equal(t, true, p5.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{}))
}

func TestArtifactNameShortPolicyMatcher(t *testing.T) {
	p1 := ArtifactNameShortPolicyMatcher{ArtifactNameShort: []string{"debian"}}
	assert.Equal(t, true, p1.IsMatch(types.Report{ArtifactName: "debian:11"}, types.Result{}, types.DetectedVulnerability{}))
	assert.Equal(t, false, p1.IsMatch(types.Report{ArtifactName: "ubuntu:22.04"}, types.Result{}, types.DetectedVulnerability{}))

	p2 := ArtifactNameShortPolicyMatcher{ArtifactNameShort: []string{"debian", "ubuntu"}}
	assert.Equal(t, true, p2.IsMatch(types.Report{ArtifactName: "debian:11"}, types.Result{}, types.DetectedVulnerability{}))
	assert.Equal(t, true, p2.IsMatch(types.Report{ArtifactName: "ubuntu:22.04"}, types.Result{}, types.DetectedVulnerability{}))
}

func TestPackageNamePolicyMatcher(t *testing.T) {
	p1 := PackageNamePolicyMatcher{PackageName: []string{"apt"}}
	assert.Equal(t, true, p1.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{PkgName: "apt"}))
	assert.Equal(t, false, p1.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{PkgName: "sh"}))

	p2 := PackageNamePolicyMatcher{PackageName: []string{"apt", "sh"}}
	assert.Equal(t, true, p2.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{PkgName: "apt"}))
	assert.Equal(t, true, p2.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{PkgName: "sh"}))
}

func TestClassPolicyMatcher(t *testing.T) {
	p1 := ClassPolicyMatcher{Class: []string{"os-pkgs"}}
	assert.Equal(t, true, p1.IsMatch(types.Report{}, types.Result{Class: "os-pkgs"}, types.DetectedVulnerability{}))
	assert.Equal(t, false, p1.IsMatch(types.Report{}, types.Result{Class: "lang-pkgs"}, types.DetectedVulnerability{}))

	p2 := ClassPolicyMatcher{Class: []string{"os-pkgs", "lang-pkgs"}}
	assert.Equal(t, true, p2.IsMatch(types.Report{}, types.Result{Class: "os-pkgs"}, types.DetectedVulnerability{}))
	assert.Equal(t, true, p2.IsMatch(types.Report{}, types.Result{Class: "lang-pkgs"}, types.DetectedVulnerability{}))
}

func TestCVSSPolicyMatcher(t *testing.T) {
	t.Run("ScoreLowerThan", func(t *testing.T) {
		p := CVSSPolicyMatcher{CVSS: CVSSPolicyMatcherCVSS{ScoreLowerThan: 5}}
		assert.Equal(t, true, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Score: 4.9}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Score: 5}}}}))
	})

	t.Run("AV", func(t *testing.T) {
		p := CVSSPolicyMatcher{CVSS: CVSSPolicyMatcherCVSS{AV: []string{"N", "A"}}}
		assert.Equal(t, true, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, true, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "MALFORMED"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{}}}}))
	})

	t.Run("AC", func(t *testing.T) {
		p := CVSSPolicyMatcher{CVSS: CVSSPolicyMatcherCVSS{AC: []string{"H"}}}
		assert.Equal(t, true, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "MALFORMED"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{}}}}))
	})

	t.Run("PR", func(t *testing.T) {
		p := CVSSPolicyMatcher{CVSS: CVSSPolicyMatcherCVSS{PR: []string{"H"}}}
		assert.Equal(t, true, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "MALFORMED"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{}}}}))
	})

	t.Run("UI", func(t *testing.T) {
		p := CVSSPolicyMatcher{CVSS: CVSSPolicyMatcherCVSS{UI: []string{"R"}}}
		assert.Equal(t, true, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "MALFORMED"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{}}}}))
	})

	t.Run("S", func(t *testing.T) {
		p := CVSSPolicyMatcher{CVSS: CVSSPolicyMatcherCVSS{S: []string{"C"}}}
		assert.Equal(t, true, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:N/I:N/A:N"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "MALFORMED"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{}}}}))
	})

	t.Run("C", func(t *testing.T) {
		p := CVSSPolicyMatcher{CVSS: CVSSPolicyMatcherCVSS{C: []string{"H"}}}
		assert.Equal(t, true, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:N/A:N"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "MALFORMED"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{}}}}))
	})

	t.Run("I", func(t *testing.T) {
		p := CVSSPolicyMatcher{CVSS: CVSSPolicyMatcherCVSS{I: []string{"H"}}}
		assert.Equal(t, true, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:N/I:H/A:N"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "MALFORMED"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{}}}}))
	})

	t.Run("A", func(t *testing.T) {
		p := CVSSPolicyMatcher{CVSS: CVSSPolicyMatcherCVSS{A: []string{"H"}}}
		assert.Equal(t, true, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:N/I:N/A:H"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "MALFORMED"}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{}}}}))
	})

	t.Run("All", func(t *testing.T) {
		p := CVSSPolicyMatcher{CVSS: CVSSPolicyMatcherCVSS{ScoreLowerThan: 5, AV: []string{"N"}, AC: []string{"H"}, PR: []string{"H"}, UI: []string{"R"}, S: []string{"C"}, C: []string{"H"}, I: []string{"H"}, A: []string{"H"}}}
		assert.Equal(t, true, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H", V3Score: 4}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H", V3Score: 5}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H", V3Score: 4}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:H", V3Score: 4}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H", V3Score: 4}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H", V3Score: 4}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H", V3Score: 4}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:N/I:H/A:H", V3Score: 4}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:H/I:N/A:H", V3Score: 4}}}}))
		assert.Equal(t, false, p.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N", V3Score: 4}}}}))
	})
}
