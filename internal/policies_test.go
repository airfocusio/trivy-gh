package internal

import (
	"testing"

	trivydbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestAndPolicyMatcher(t *testing.T) {
	p1 := AndPolicyMatcher{}
	assert.Equal(t, true, p1.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{}))
	p2 := AndPolicyMatcher{Inner: []PolicyMatcher{&YesPolicyMatcher{}}}
	assert.Equal(t, true, p2.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{}))
	p3 := AndPolicyMatcher{Inner: []PolicyMatcher{&YesPolicyMatcher{}, &YesPolicyMatcher{}}}
	assert.Equal(t, true, p3.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{}))
	p4 := AndPolicyMatcher{Inner: []PolicyMatcher{&NoPolicyMatcher{}}}
	assert.Equal(t, false, p4.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{}))
	p5 := AndPolicyMatcher{Inner: []PolicyMatcher{&YesPolicyMatcher{}, &NoPolicyMatcher{}}}
	assert.Equal(t, false, p5.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{}))
}

func TestOrPolicyMatcher(t *testing.T) {
	p1 := OrPolicyMatcher{}
	assert.Equal(t, false, p1.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{}))
	p2 := OrPolicyMatcher{Inner: []PolicyMatcher{&YesPolicyMatcher{}}}
	assert.Equal(t, true, p2.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{}))
	p3 := OrPolicyMatcher{Inner: []PolicyMatcher{&YesPolicyMatcher{}, &YesPolicyMatcher{}}}
	assert.Equal(t, true, p3.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{}))
	p4 := OrPolicyMatcher{Inner: []PolicyMatcher{&NoPolicyMatcher{}}}
	assert.Equal(t, false, p4.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{}))
	p5 := OrPolicyMatcher{Inner: []PolicyMatcher{&YesPolicyMatcher{}, &NoPolicyMatcher{}}}
	assert.Equal(t, true, p5.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{}))
}

func TestArtifactNameShortPolicyMatcher(t *testing.T) {
	p1 := ArtifactNameShortPolicyMatcher{ArtifactNameShort: []string{"ghcr.io/airfocusio/trivy-gh-test-debian"}}
	assert.Equal(t, true, p1.IsMatch(types.Report{ArtifactName: "ghcr.io/airfocusio/trivy-gh-test-debian:11"}, types.Result{}, types.DetectedVulnerability{}))
	assert.Equal(t, false, p1.IsMatch(types.Report{ArtifactName: "ghcr.io/airfocusio/trivy-gh-test-ubuntu:22.04"}, types.Result{}, types.DetectedVulnerability{}))

	p2 := ArtifactNameShortPolicyMatcher{ArtifactNameShort: []string{"ghcr.io/airfocusio/trivy-gh-test-debian", "ghcr.io/airfocusio/trivy-gh-test-ubuntu"}}
	assert.Equal(t, true, p2.IsMatch(types.Report{ArtifactName: "ghcr.io/airfocusio/trivy-gh-test-debian:11"}, types.Result{}, types.DetectedVulnerability{}))
	assert.Equal(t, true, p2.IsMatch(types.Report{ArtifactName: "ghcr.io/airfocusio/trivy-gh-test-ubuntu:22.04"}, types.Result{}, types.DetectedVulnerability{}))
}

func TestPackageNamePolicyMatcher(t *testing.T) {
	p1 := PackageNamePolicyMatcher{PackageName: []string{"apt"}}
	assert.Equal(t, true, p1.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{PkgName: "apt"}))
	assert.Equal(t, false, p1.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{PkgName: "sh"}))

	p2 := PackageNamePolicyMatcher{PackageName: []string{"apt", "sh"}}
	assert.Equal(t, true, p2.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{PkgName: "apt"}))
	assert.Equal(t, true, p2.IsMatch(types.Report{}, types.Result{}, types.DetectedVulnerability{PkgName: "sh"}))
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
}
