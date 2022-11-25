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

	scan := NewScan(NewNullLogger(), Config{}, "../example", true, 0)

	if files, err := scan.ScrapeFile(file); assert.NoError(t, err) {
		assert.Equal(t, []string{"image1:v1", "image2:v1", "image3:v1"}, files)
	}
}

func TestFindMatchingPolicies(t *testing.T) {
	t.Run("MatchAll", func(t *testing.T) {
		p1 := ConfigPolicy{Match: &YesPolicyMatcher{}}
		scan := NewScan(NewNullLogger(), Config{
			Policies: []ConfigPolicy{p1},
		}, "../example", true, 0)

		assert.Equal(t, &p1, scan.FindMatchingPolicy(types.Report{}, types.Result{}, types.DetectedVulnerability{}))
	})
}

func TestRenderGithubIssueBody(t *testing.T) {
	resetGithubToken := temporarySetenv("GITHUB_TOKEN", "token")
	defer resetGithubToken()
	scan := NewScan(NewNullLogger(), Config{}, "../example", true, 0)

	assert.Equal(t, "| Key | Value\n"+
		"|---|---\n"+
		"| ID | CVE-2011-3374\n"+
		"| CVSS Score | low (3.7)\n"+
		"| CVSS Vector | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N\n"+
		"| Artifact | debian:11\n"+
		"| Package | apt\n"+
		"| Installed Version | 2.2.4\n"+
		"| Fixed Version |\n"+
		"| Published | <nil>\n"+
		"\n"+
		"### Description\n"+
		"\n"+
		"### References\n"+
		"\n"+
		"https://domain.com/main\n"+
		"https://domain.com/path1\n"+
		"https://domain.com/path2\n"+
		"\n"+
		"<!-- id=abc123 -->",
		scan.RenderGithubIssueBody(types.Report{
			ArtifactName: "debian:11",
		}, types.Result{}, types.DetectedVulnerability{
			VulnerabilityID:  "CVE-2011-3374",
			PkgName:          "apt",
			InstalledVersion: "2.2.4",
			PrimaryURL:       "https://domain.com/main",
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
		}, "<!-- id=abc123 -->"))
}

func TestRenderGithubDashboardIssueBody(t *testing.T) {
	resetGithubToken := temporarySetenv("GITHUB_TOKEN", "token")
	defer resetGithubToken()
	scan := NewScan(NewNullLogger(), Config{}, "../example", true, 0)
	issueNumber := 1

	assert.Equal(t, "<!-- id=abc123 -->",
		scan.RenderGithubDashboardIssueBody([]ProcessedUnfixedVulnerability{}, "<!-- id=abc123 -->"))

	assert.Equal(t, "### Rate limited\n"+
		"\n"+
		"The following issues have not been created yet, as the rate limit for issue creation has been exceeded. They will be created later.\n"+
		"\n"+
		"#### rate-limited:1.2.3\n"+
		"\n"+
		"- [ ] [CVE-1](https://domain.com/cve-1) **low** (0.1) `pkg1`\n"+
		"- [ ] [CVE-2](https://domain.com/cve-2) **medium** (4.0) `pkg2`\n"+
		"\n"+
		"#### rate-limited-2:1.2.3\n"+
		"\n"+
		"- [ ] [CVE-3](https://domain.com/cve-3) **high** (7.0) `pkg3`\n"+
		"\n"+
		"### Mitigated\n"+
		"\n"+
		"The following issues are still found, but have been marked as mitigated by some policy. They will stay here in this list until finally fixed.\n"+
		"\n"+
		"#### mitigated:1.2.3\n"+
		"\n"+
		"- [ ] [CVE-0](https://domain.com/cve-0) **critical** (10.0) `pkg0`: Mitigation: Policy\n"+
		"\n"+
		"<!-- id=abc123 -->",
		scan.RenderGithubDashboardIssueBody([]ProcessedUnfixedVulnerability{
			{
				issueNumber: &issueNumber,
				report: types.Report{
					ArtifactName: "mitigated:1.2.3",
				},
				vulnerability: types.DetectedVulnerability{
					VulnerabilityID: "CVE-0",
					PrimaryURL:      "https://domain.com/cve-0",
					PkgName:         "pkg0",
					Vulnerability: trivydbtypes.Vulnerability{
						CVSS: trivydbtypes.VendorCVSS{
							"nvd": trivydbtypes.CVSS{
								V3Score: 10,
							},
						},
					},
				},
				mitigations: []Mitigation{{
					Mitigation: ConfigMitigation{
						Label: "Mitigation",
					},
					Policy: ConfigPolicy{
						Comment: "Policy",
					},
				}},
			},
			{
				report: types.Report{
					ArtifactName: "rate-limited:1.2.3",
				},
				vulnerability: types.DetectedVulnerability{
					VulnerabilityID: "CVE-1",
					PrimaryURL:      "https://domain.com/cve-1",
					PkgName:         "pkg1",
					Vulnerability: trivydbtypes.Vulnerability{
						CVSS: trivydbtypes.VendorCVSS{
							"nvd": trivydbtypes.CVSS{
								V3Score: 0.1,
							},
						},
					},
				},
			},
			{
				report: types.Report{
					ArtifactName: "rate-limited:1.2.3",
				},
				vulnerability: types.DetectedVulnerability{
					VulnerabilityID: "CVE-2",
					PrimaryURL:      "https://domain.com/cve-2",
					PkgName:         "pkg2",
					Vulnerability: trivydbtypes.Vulnerability{
						CVSS: trivydbtypes.VendorCVSS{
							"nvd": trivydbtypes.CVSS{
								V3Score: 4,
							},
						},
					},
				},
			},
			{
				report: types.Report{
					ArtifactName: "rate-limited-2:1.2.3",
				},
				vulnerability: types.DetectedVulnerability{
					VulnerabilityID: "CVE-3",
					PrimaryURL:      "https://domain.com/cve-3",
					PkgName:         "pkg3",
					Vulnerability: trivydbtypes.Vulnerability{
						CVSS: trivydbtypes.VendorCVSS{
							"nvd": trivydbtypes.CVSS{
								V3Score: 7,
							},
						},
					},
				},
			},
		}, "<!-- id=abc123 -->"))
}

func TestScan(t *testing.T) {
	githubToken := os.Getenv("GITHUB_TOKEN")
	if githubToken == "" {
		t.SkipNow()
	}

	rand.Seed(time.Now().Unix())
	randNum := rand.Int()
	artifactNameShort := "test-artifact-" + strconv.Itoa(randNum)
	artifactName := artifactNameShort + ":1.0.0"
	packageName := "test-package-" + strconv.Itoa(randNum)
	vulnerabilityId := "TEST-" + strconv.Itoa(randNum)
	mitigationKey := "too-unimportant-" + strconv.Itoa(randNum)

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
	}, "../example", false, 10)

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
	issueNumbers1, err := scan.ProcessUnfixedVulnerability(artifactNameShort, report1, report1.Results[0], report1.Results[0].Vulnerabilities[0])
	assert.NoError(t, err)
	issueNumber := *issueNumbers1.issueNumber
	defer func() {
		closed := "closed"
		scan.githubClient.Issues.Edit(scan.ctx, scan.config.Github.IssueRepoOwner, scan.config.Github.IssueRepoName, issueNumber, &github.IssueRequest{
			State: &closed,
		})
		labels := []string{}
		for _, l := range generateVulnerabilityLabels(artifactNameShort, report1.Results[0].Vulnerabilities[0]) {
			if !strings.HasPrefix(l, "s:") {
				labels = append(labels, l)
			}
		}
		for _, l := range labels {
			scan.githubClient.Issues.DeleteLabel(scan.ctx, scan.config.Github.IssueRepoOwner, scan.config.Github.IssueRepoName, l)
		}
	}()

	if issue, _, err := scan.githubClient.Issues.Get(scan.ctx, scan.config.Github.IssueRepoOwner, scan.config.Github.IssueRepoName, issueNumber); assert.NoError(t, err) {
		assert.Contains(t, *issue.Body, fmt.Sprintf("id=%s/%s/%s", artifactNameShort, packageName, vulnerabilityId))
		assert.Equal(t, "open", *issue.State)
	}

	// not close as it is not yet fixed
	issueNumbers2, err := scan.ProcessFixedVulnerabilities(artifactNameShort, []int{issueNumber})
	assert.NoError(t, err)
	assert.Empty(t, issueNumbers2)
	if issue, _, err := scan.githubClient.Issues.Get(scan.ctx, scan.config.Github.IssueRepoOwner, scan.config.Github.IssueRepoName, issueNumber); assert.NoError(t, err) {
		assert.Equal(t, "open", *issue.State)
	}

	// keep additional labels
	additionalLabelName := "additional"
	additionalWithLabels := append(generateVulnerabilityLabels(artifactNameShort, report1.Results[0].Vulnerabilities[0]), additionalLabelName)
	if _, _, err := scan.githubClient.Issues.Edit(scan.ctx, scan.config.Github.IssueRepoOwner, scan.config.Github.IssueRepoName, issueNumber, &github.IssueRequest{
		Labels: &additionalWithLabels,
	}); assert.NoError(t, err) {
		issueNumbers3, err := scan.ProcessFixedVulnerabilities(artifactNameShort, []int{issueNumber})
		assert.NoError(t, err)
		assert.Empty(t, issueNumbers3)
		if issue, _, err := scan.githubClient.Issues.Get(scan.ctx, scan.config.Github.IssueRepoOwner, scan.config.Github.IssueRepoName, issueNumber); assert.NoError(t, err) {
			assert.Equal(t, "open", *issue.State)
			containsAdditionalLabel := false
			for _, l := range issue.Labels {
				if *l.Name == additionalLabelName {
					containsAdditionalLabel = true
					break
				}
			}
			assert.True(t, containsAdditionalLabel)
		}
	}

	// close as it is fixed
	issueNumbers4, err := scan.ProcessFixedVulnerabilities(artifactNameShort, []int{})
	assert.NoError(t, err)
	assert.Equal(t, []int{issueNumber}, issueNumbers4)
	if issue, _, err := scan.githubClient.Issues.Get(scan.ctx, scan.config.Github.IssueRepoOwner, scan.config.Github.IssueRepoName, issueNumber); assert.NoError(t, err) {
		assert.Equal(t, "closed", *issue.State)
	}

	// reopen as it has come back
	issueNumbers5, err := scan.ProcessUnfixedVulnerability(artifactNameShort, report1, report1.Results[0], report1.Results[0].Vulnerabilities[0])
	assert.NoError(t, err)
	assert.Equal(t, issueNumber, *issueNumbers5.issueNumber)
	if issue, _, err := scan.githubClient.Issues.Get(scan.ctx, scan.config.Github.IssueRepoOwner, scan.config.Github.IssueRepoName, issueNumber); assert.NoError(t, err) {
		assert.Equal(t, "open", *issue.State)
	}

	// close again as it is mitigated by policy
	issueNumbers6, err := scan.ProcessUnfixedVulnerability(artifactNameShort, report2, report2.Results[0], report2.Results[0].Vulnerabilities[0])
	assert.NoError(t, err)
	assert.Equal(t, issueNumber, *issueNumbers6.issueNumber)
	if issue, _, err := scan.githubClient.Issues.Get(scan.ctx, scan.config.Github.IssueRepoOwner, scan.config.Github.IssueRepoName, issueNumber); assert.NoError(t, err) {
		assert.Equal(t, "closed", *issue.State)
	}
}
