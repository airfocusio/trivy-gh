package internal

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	trivydbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/google/go-github/v48/github"
	"github.com/stretchr/testify/assert"
)

func TestScanScrapeFile(t *testing.T) {
	file := path.Join(os.TempDir(), fmt.Sprintf("trivy-gh-%d.yaml", time.Now().UnixNano()))
	if err := ioutil.WriteFile(file, []byte(`
foo:
- image: image1:v1
- bar:
    image: image2:v1
---
image: image3:v1
`), 0o644); err != nil {
		panic(err)
	}
	defer os.Remove(file)

	scan := NewScan(NewNullLogger(), Config{}, "../example", true, 0, 0)

	if files, err := scan.ScrapeFile(file); assert.NoError(t, err) {
		assert.Equal(t, []string{"image1:v1", "image2:v1", "image3:v1"}, files)
	}
}

func TestFindMatchingPolicies(t *testing.T) {
	t.Run("MatchAll", func(t *testing.T) {
		p1 := ConfigPolicy{Match: &YesPolicyMatcher{}}
		scan := NewScan(NewNullLogger(), Config{
			Policies: []ConfigPolicy{p1},
		}, "../example", true, 0, 0)

		assert.Equal(t, []ConfigPolicy{p1}, scan.EvaluateMatchingPolicies(types.Report{}, types.Result{}, types.DetectedVulnerability{}))
	})
}

func TestRenderGithubIssueBody(t *testing.T) {
	resetGithubToken := temporarySetenv("GITHUB_TOKEN", "token")
	defer resetGithubToken()

	scan := NewScan(NewNullLogger(), Config{}, "../example", true, 0, 0)

	assert.Equal(t, strings.Trim(`
| Key | Value
|---|---
| ID | CVE-2011-3374
| CVSS Score | 3.7
| CVSS Vector | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N
| Artifact | debian:11
| Package | apt
| Installed Version | 2.2.4
| Fixed Version |
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
		ArtifactName: "debian:11",
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

func TestScan(t *testing.T) {
	githubToken := os.Getenv("GITHUB_TOKEN")
	if githubToken == "" {
		t.SkipNow()
	}

	rand.Seed(time.Now().Unix())
	artifactNameShort := "test-artifact-" + strconv.Itoa(rand.Int())
	artifactName := artifactNameShort + ":1.0.0"
	packageName := "test-package-" + strconv.Itoa(rand.Int())
	vulnerabilityId := "TEST-" + strconv.Itoa(rand.Int())
	mitigationKey := "too-unimportant-" + strconv.Itoa(rand.Int())

	scan := NewScan(NewNullLogger(), Config{
		Github: ConfigGithub{
			Token:          githubToken,
			IssueRepoOwner: "airfocusio",
			IssueRepoName:  "trivy-gh-test",
		},
		Mitigations: []ConfigMitigation{
			{
				Key:   mitigationKey,
				Label: "Too unimportant",
			},
		},
		Policies: []ConfigPolicy{
			{
				Match: &CVSSPolicyMatcher{
					CVSS: CVSSPolicyMatcherCVSS{
						ScoreLowerThan: 4,
					},
				},
				Mitigate: []string{mitigationKey},
			},
		},
	}, "../example", false, 10, 10)

	report1 := types.Report{
		ArtifactName: artifactName,
		Results: types.Results{
			{
				Vulnerabilities: []types.DetectedVulnerability{
					{
						VulnerabilityID: vulnerabilityId,
						PkgName:         packageName,
						Vulnerability: trivydbtypes.Vulnerability{
							Title:       "Test title",
							Description: "Test description",
							Severity:    "HIGH",
							CVSS: trivydbtypes.VendorCVSS{
								"nvd": trivydbtypes.CVSS{
									V3Score:  7.8,
									V3Vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
								},
							},
							References: []string{"https://domain.com"},
						},
					},
				},
			},
		},
	}
	report2 := types.Report{
		ArtifactName: artifactName,
		Results: types.Results{
			{
				Vulnerabilities: []types.DetectedVulnerability{
					{
						VulnerabilityID: vulnerabilityId,
						PkgName:         packageName,
						Vulnerability: trivydbtypes.Vulnerability{
							Title:       "Test title",
							Description: "Test description",
							Severity:    "LOW",
							CVSS: trivydbtypes.VendorCVSS{
								"nvd": trivydbtypes.CVSS{
									V3Score:  0.1,
									V3Vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N",
								},
							},
							References: []string{"https://domain.com"},
						},
					},
				},
			},
		},
	}

	// create
	issueNumbers1, err := scan.ProcessUnfixedIssues(artifactNameShort, []*types.Report{&report1})
	assert.NoError(t, err)
	assert.Len(t, issueNumbers1, 1)
	issueNumber := issueNumbers1[0]
	defer func() {
		closed := "closed"
		scan.githubClient.Issues.Edit(scan.ctx, scan.config.Github.IssueRepoOwner, scan.config.Github.IssueRepoName, issueNumber, &github.IssueRequest{
			State: &closed,
		})
		scan.githubClient.Issues.DeleteLabel(scan.ctx, scan.config.Github.IssueRepoOwner, scan.config.Github.IssueRepoName, artifactNameShort)
		scan.githubClient.Issues.DeleteLabel(scan.ctx, scan.config.Github.IssueRepoOwner, scan.config.Github.IssueRepoName, vulnerabilityId)
	}()

	if issue, _, err := scan.githubClient.Issues.Get(scan.ctx, scan.config.Github.IssueRepoOwner, scan.config.Github.IssueRepoName, issueNumber); assert.NoError(t, err) {
		assert.NoError(t, err)
		assert.Contains(t, *issue.Body, fmt.Sprintf("id=%s/%s/%s", artifactNameShort, packageName, vulnerabilityId))
		assert.Equal(t, "open", *issue.State)
	}

	// not close as it is not yet fixed
	issueNumbers2, err := scan.ProcessFixedIssues(artifactNameShort, []int{issueNumber})
	assert.NoError(t, err)
	assert.Empty(t, issueNumbers2)
	if issue, _, err := scan.githubClient.Issues.Get(scan.ctx, scan.config.Github.IssueRepoOwner, scan.config.Github.IssueRepoName, issueNumber); assert.NoError(t, err) {
		assert.NoError(t, err)
		assert.Equal(t, "open", *issue.State)
	}

	// close as it is fixed
	issueNumbers3, err := scan.ProcessFixedIssues(artifactNameShort, []int{})
	assert.NoError(t, err)
	assert.Equal(t, []int{issueNumber}, issueNumbers3)
	if issue, _, err := scan.githubClient.Issues.Get(scan.ctx, scan.config.Github.IssueRepoOwner, scan.config.Github.IssueRepoName, issueNumber); assert.NoError(t, err) {
		assert.NoError(t, err)
		assert.Equal(t, "closed", *issue.State)
	}

	// reopen as it has come back
	issueNumbers4, err := scan.ProcessUnfixedIssues(artifactNameShort, []*types.Report{&report1})
	assert.NoError(t, err)
	assert.Equal(t, []int{issueNumber}, issueNumbers4)
	if issue, _, err := scan.githubClient.Issues.Get(scan.ctx, scan.config.Github.IssueRepoOwner, scan.config.Github.IssueRepoName, issueNumber); assert.NoError(t, err) {
		assert.NoError(t, err)
		assert.Equal(t, "open", *issue.State)
	}

	// close again as it is mitigated by policy
	issueNumbers, err := scan.ProcessUnfixedIssues(artifactNameShort, []*types.Report{&report2})
	assert.NoError(t, err)
	assert.Equal(t, []int{issueNumber}, issueNumbers)
	if issue, _, err := scan.githubClient.Issues.Get(scan.ctx, scan.config.Github.IssueRepoOwner, scan.config.Github.IssueRepoName, issueNumber); assert.NoError(t, err) {
		assert.NoError(t, err)
		assert.Equal(t, "closed", *issue.State)
		assert.Contains(t, *issue.Body, fmt.Sprintf("policy-based-mitigation=%s", mitigationKey))
	}
}
