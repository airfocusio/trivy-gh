package internal

import (
	"os"
	"strings"
	"testing"

	trivydbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestScanScrapeFile(t *testing.T) {
	os.Setenv("GITHUB_TOKEN", "token")
	scan := NewScan(NewNullLogger(), Config{}, "../example", true, 0, 0)

	f1, e1 := scan.ScrapeFile("../example/k8s/deployment1.yaml")
	assert.NoError(t, e1)
	assert.Equal(t, []string{"ghcr.io/airfocusio/trivy-gh-test-debian:11", "ghcr.io/airfocusio/trivy-gh-test-ubuntu:22.04"}, f1)

	f2, e2 := scan.ScrapeFile("../example/k8s/deployment2.yaml")
	assert.NoError(t, e2)
	assert.Equal(t, []string{"ghcr.io/airfocusio/trivy-gh-test-alpine:3.14", "ghcr.io/airfocusio/trivy-gh-test-debian:11"}, f2)
}

func TestFindMatchingPolicies(t *testing.T) {
	os.Setenv("GITHUB_TOKEN", "token")

	t.Run("MatchAll", func(t *testing.T) {
		p1 := ConfigPolicy{Match: ConfigPolicyMatch{}}
		scan := NewScan(NewNullLogger(), Config{
			Policies:    []ConfigPolicy{p1},
			CVSSSources: []trivydbtypes.SourceID{"nvd"},
		}, "../example", true, 0, 0)

		assert.Equal(t, []ConfigPolicy{p1}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{}))
	})

	t.Run("MatchArtifactNameShort", func(t *testing.T) {
		p1 := ConfigPolicy{Match: ConfigPolicyMatch{ArtifactNameShort: "ghcr.io/airfocusio/trivy-gh-test-debian"}}
		scan := NewScan(NewNullLogger(), Config{
			Policies:    []ConfigPolicy{p1},
			CVSSSources: []trivydbtypes.SourceID{"nvd"},
		}, "../example", true, 0, 0)

		assert.Equal(t, []ConfigPolicy{p1}, scan.FindMatchingPolicies(types.Report{ArtifactName: "ghcr.io/airfocusio/trivy-gh-test-debian:11"}, types.Result{}, types.DetectedVulnerability{}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{ArtifactName: "ghcr.io/airfocusio/trivy-gh-test-ubuntu:22.04"}, types.Result{}, types.DetectedVulnerability{}))
	})

	t.Run("MatchPkgName", func(t *testing.T) {
		p1 := ConfigPolicy{Match: ConfigPolicyMatch{PkgName: "apt"}}
		scan := NewScan(NewNullLogger(), Config{
			Policies:    []ConfigPolicy{p1},
			CVSSSources: []trivydbtypes.SourceID{"nvd"},
		}, "../example", true, 0, 0)

		assert.Equal(t, []ConfigPolicy{p1}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{PkgName: "apt"}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{PkgName: "sh"}))
	})

	t.Run("MatchCVSSScoreLowerThan", func(t *testing.T) {
		p1 := ConfigPolicy{Match: ConfigPolicyMatch{CVSS: ConfigPolicyMatchCVSS{ScoreLowerThan: 5}}}
		scan := NewScan(NewNullLogger(), Config{
			Policies:    []ConfigPolicy{p1},
			CVSSSources: []trivydbtypes.SourceID{"nvd"},
		}, "../example", true, 0, 0)

		assert.Equal(t, []ConfigPolicy{p1}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Score: 4.9}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Score: 5}}}}))
	})

	t.Run("MatchCVSSAV", func(t *testing.T) {
		p1 := ConfigPolicy{Match: ConfigPolicyMatch{CVSS: ConfigPolicyMatchCVSS{AV: []string{"N", "A"}}}}
		scan := NewScan(NewNullLogger(), Config{
			Policies:    []ConfigPolicy{p1},
			CVSSSources: []trivydbtypes.SourceID{"nvd"},
		}, "../example", true, 0, 0)

		assert.Equal(t, []ConfigPolicy{p1}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, []ConfigPolicy{p1}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "MALFORMED"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{}}}}))
	})

	t.Run("MatchCVSSAC", func(t *testing.T) {
		p1 := ConfigPolicy{Match: ConfigPolicyMatch{CVSS: ConfigPolicyMatchCVSS{AC: []string{"H"}}}}
		scan := NewScan(NewNullLogger(), Config{
			Policies:    []ConfigPolicy{p1},
			CVSSSources: []trivydbtypes.SourceID{"nvd"},
		}, "../example", true, 0, 0)

		assert.Equal(t, []ConfigPolicy{p1}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "MALFORMED"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{}}}}))
	})

	t.Run("MatchCVSSPR", func(t *testing.T) {
		p1 := ConfigPolicy{Match: ConfigPolicyMatch{CVSS: ConfigPolicyMatchCVSS{PR: []string{"H"}}}}
		scan := NewScan(NewNullLogger(), Config{
			Policies:    []ConfigPolicy{p1},
			CVSSSources: []trivydbtypes.SourceID{"nvd"},
		}, "../example", true, 0, 0)

		assert.Equal(t, []ConfigPolicy{p1}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "MALFORMED"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{}}}}))
	})

	t.Run("MatchCVSSS", func(t *testing.T) {
		p1 := ConfigPolicy{Match: ConfigPolicyMatch{CVSS: ConfigPolicyMatchCVSS{S: []string{"C"}}}}
		scan := NewScan(NewNullLogger(), Config{
			Policies:    []ConfigPolicy{p1},
			CVSSSources: []trivydbtypes.SourceID{"nvd"},
		}, "../example", true, 0, 0)

		assert.Equal(t, []ConfigPolicy{p1}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:N/I:N/A:N"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "MALFORMED"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{}}}}))
	})

	t.Run("MatchCVSC", func(t *testing.T) {
		p1 := ConfigPolicy{Match: ConfigPolicyMatch{CVSS: ConfigPolicyMatchCVSS{C: []string{"H"}}}}
		scan := NewScan(NewNullLogger(), Config{
			Policies:    []ConfigPolicy{p1},
			CVSSSources: []trivydbtypes.SourceID{"nvd"},
		}, "../example", true, 0, 0)

		assert.Equal(t, []ConfigPolicy{p1}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:N/A:N"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "MALFORMED"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{}}}}))
	})

	t.Run("MatchCVSI", func(t *testing.T) {
		p1 := ConfigPolicy{Match: ConfigPolicyMatch{CVSS: ConfigPolicyMatchCVSS{I: []string{"H"}}}}
		scan := NewScan(NewNullLogger(), Config{
			Policies:    []ConfigPolicy{p1},
			CVSSSources: []trivydbtypes.SourceID{"nvd"},
		}, "../example", true, 0, 0)

		assert.Equal(t, []ConfigPolicy{p1}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:N/I:H/A:N"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "MALFORMED"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{}}}}))
	})

	t.Run("MatchCVSA", func(t *testing.T) {
		p1 := ConfigPolicy{Match: ConfigPolicyMatch{CVSS: ConfigPolicyMatchCVSS{A: []string{"H"}}}}
		scan := NewScan(NewNullLogger(), Config{
			Policies:    []ConfigPolicy{p1},
			CVSSSources: []trivydbtypes.SourceID{"nvd"},
		}, "../example", true, 0, 0)

		assert.Equal(t, []ConfigPolicy{p1}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:N/I:N/A:H"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "CVSS:3.0"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Vector: "MALFORMED"}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{}}}}))
	})

	t.Run("MatchCombinations", func(t *testing.T) {
		p1 := ConfigPolicy{
			Match: ConfigPolicyMatch{
				ArtifactNameShort: "ghcr.io/airfocusio/trivy-gh-test-debian",
				PkgName:           "apt",
				CVSS:              ConfigPolicyMatchCVSS{ScoreLowerThan: 5},
			},
		}
		scan := NewScan(NewNullLogger(), Config{
			Policies:    []ConfigPolicy{p1},
			CVSSSources: []trivydbtypes.SourceID{"nvd"},
		}, "../example", true, 0, 0)

		assert.Equal(t, []ConfigPolicy{p1}, scan.FindMatchingPolicies(types.Report{ArtifactName: "ghcr.io/airfocusio/trivy-gh-test-debian:11"}, types.Result{}, types.DetectedVulnerability{PkgName: "apt", Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Score: 4.9}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{ArtifactName: "ghcr.io/airfocusio/trivy-gh-test-ubuntu:22.04"}, types.Result{}, types.DetectedVulnerability{PkgName: "apt", Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Score: 4.9}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{ArtifactName: "ghcr.io/airfocusio/trivy-gh-test-debian:11"}, types.Result{}, types.DetectedVulnerability{PkgName: "sh", Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Score: 4.9}}}}))
		assert.Equal(t, []ConfigPolicy{}, scan.FindMatchingPolicies(types.Report{ArtifactName: "ghcr.io/airfocusio/trivy-gh-test-debian:11"}, types.Result{}, types.DetectedVulnerability{PkgName: "apt", Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Score: 5}}}}))
	})

	t.Run("MatchMultiple", func(t *testing.T) {
		p1 := ConfigPolicy{Match: ConfigPolicyMatch{ArtifactNameShort: "ghcr.io/airfocusio/trivy-gh-test-debian"}}
		p2 := ConfigPolicy{Match: ConfigPolicyMatch{PkgName: "apt"}}
		p3 := ConfigPolicy{Match: ConfigPolicyMatch{CVSS: ConfigPolicyMatchCVSS{ScoreLowerThan: 5}}}
		scan := NewScan(NewNullLogger(), Config{
			Policies:    []ConfigPolicy{p1, p2, p3},
			CVSSSources: []trivydbtypes.SourceID{"nvd"},
		}, "../example", true, 0, 0)

		assert.Equal(t, []ConfigPolicy{p1, p2, p3}, scan.FindMatchingPolicies(types.Report{ArtifactName: "ghcr.io/airfocusio/trivy-gh-test-debian:11"}, types.Result{}, types.DetectedVulnerability{PkgName: "apt", Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Score: 4.9}}}}))
		assert.Equal(t, []ConfigPolicy{p2, p3}, scan.FindMatchingPolicies(types.Report{ArtifactName: "ghcr.io/airfocusio/trivy-gh-test-ubuntu:22.04"}, types.Result{}, types.DetectedVulnerability{PkgName: "apt", Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Score: 4.9}}}}))
		assert.Equal(t, []ConfigPolicy{p1, p3}, scan.FindMatchingPolicies(types.Report{ArtifactName: "ghcr.io/airfocusio/trivy-gh-test-debian:11"}, types.Result{}, types.DetectedVulnerability{PkgName: "sh", Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Score: 4.9}}}}))
		assert.Equal(t, []ConfigPolicy{p1, p2}, scan.FindMatchingPolicies(types.Report{ArtifactName: "ghcr.io/airfocusio/trivy-gh-test-debian:11"}, types.Result{}, types.DetectedVulnerability{PkgName: "apt", Vulnerability: trivydbtypes.Vulnerability{CVSS: trivydbtypes.VendorCVSS{"nvd": trivydbtypes.CVSS{V3Score: 5}}}}))
	})
}

func TestRenderGithubIssueBody(t *testing.T) {
	os.Setenv("GITHUB_TOKEN", "token")
	scan := NewScan(NewNullLogger(), Config{CVSSSources: []trivydbtypes.SourceID{"nvd"}}, "../example", true, 0, 0)

	assert.Equal(t, strings.Trim(`
| Key | Value
|---|---
| ID | CVE-2011-3374
| CVSS | 3.7
| CVSS Vector | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N
| Artifact | ghcr.io/airfocusio/trivy-gh-test-debian:11
| Package | apt
| Installed version | 2.2.4
| Fixed version |
| Published | <nil>

### Manual mitigations

- [ ] <!-- manual-mitigation=k1 --> Label 1
- [x] <!-- manual-mitigation=k2 --> Label 2

### Policy-based mitigations

- [x] <!-- policy-based-mitigation=k3 --> Label 3
- [x] <!-- policy-based-mitigation=k4 --> Label 4: Comment 1
- [x] <!-- policy-based-mitigation=k5 --> Label 5: Comment 2
- [x] <!-- policy-based-mitigation=k5 --> Label 5: Comment 3a Comment 3b

### Description

### References

https://domain.com/path1
https://domain.com/path2

<!-- id=abc123 -->
`, "\n "), scan.RenderGithubIssueBody(types.Report{
		ArtifactName: "ghcr.io/airfocusio/trivy-gh-test-debian:11",
	}, types.Result{}, types.DetectedVulnerability{
		VulnerabilityID:  "CVE-2011-3374",
		PkgName:          "apt",
		InstalledVersion: "2.2.4",
		Vulnerability: trivydbtypes.Vulnerability{
			CVSS: trivydbtypes.VendorCVSS{
				"nvd": trivydbtypes.CVSS{
					V3Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
					V3Score:  3.7,
				},
			},
			References: []string{
				"https://domain.com/path1",
				"https://domain.com/path2",
			},
		},
	}, []ManualMitigationTask{
		{Done: false, Mitigation: ConfigMitigation{Key: "k1", Label: "Label 1", AllowManual: true}},
		{Done: true, Mitigation: ConfigMitigation{Key: "k2", Label: "Label 2", AllowManual: true}},
	}, []PolicyBasedMitigationTask{
		{Done: true, Mitigation: ConfigMitigation{Key: "k3", Label: "Label 3"}, Policy: ConfigPolicy{}},
		{Done: true, Mitigation: ConfigMitigation{Key: "k4", Label: "Label 4"}, Policy: ConfigPolicy{Comment: "Comment 1"}},
		{Done: true, Mitigation: ConfigMitigation{Key: "k5", Label: "Label 5"}, Policy: ConfigPolicy{Comment: "Comment 2"}},
		{Done: true, Mitigation: ConfigMitigation{Key: "k5", Label: "Label 5"}, Policy: ConfigPolicy{Comment: "Comment 3a\nComment 3b\n"}},
	}, "<!-- id=abc123 -->"))
}
