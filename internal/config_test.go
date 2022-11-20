package internal

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	resetGithubToken := temporarySetenv("GITHUB_TOKEN", "token")
	defer resetGithubToken()

	bytes, err := os.ReadFile("../example/.trivy-gh.yaml")
	assert.NoError(t, err)

	c1, err := LoadConfig(bytes)
	if assert.NoError(t, err) {
		c2 := &Config{
			Github: ConfigGithub{
				Token:          "token",
				IssueRepoOwner: "airfocusio",
				IssueRepoName:  "trivy-gh-test",
			},
			Files: []regexp.Regexp{
				*regexp.MustCompile("^/k8s/.*.yaml"),
			},
			Mitigations: []ConfigMitigation{
				{
					Key:         "not-used",
					Label:       "Not used",
					AllowManual: true,
				},
				{
					Key:         "no-public-networking",
					Label:       "No public networking",
					AllowManual: true,
				},
			},
			Policies: []ConfigPolicy{
				{
					Comment: "Can only be executed from inside the container.\n",
					Match: &AndPolicyMatcher{
						Inner: []PolicyMatcher{
							&PackageNamePolicyMatcher{
								PackageName: []string{"sh", "bash"},
							},
						},
					},
					Mitigate: []string{"not-used"},
				},
				{
					Comment: "This container is purely internal.\nSo we can ignore it.\n",
					Match: &AndPolicyMatcher{
						Inner: []PolicyMatcher{
							&ArtifactNameShortPolicyMatcher{
								ArtifactNameShort: []string{"ghcr.io/airfocusio/trivy-gh-test-debian"},
							},
							&CVSSPolicyMatcher{
								CVSS: CVSSPolicyMatcherCVSS{
									AV: []string{"N"},
								},
							},
						},
					},
					Mitigate: []string{"no-public-networking"},
				},
				{
					Match: &AndPolicyMatcher{
						Inner: []PolicyMatcher{
							&CVSSPolicyMatcher{
								CVSS: CVSSPolicyMatcherCVSS{
									ScoreLowerThan: 8.5,
								},
							},
						},
					},
					Ignore: true,
				},
				{
					Match: &AndPolicyMatcher{
						Inner: []PolicyMatcher{
							&IDPolicyMatcher{
								ID: []string{"CVE-0"},
							},
						},
					},
					Ignore: true,
				},
			},
		}
		assert.Equal(t, c2.Github, c1.Github)
		assert.Equal(t, c2.Files, c1.Files)
		assert.Equal(t, c2.Policies, c1.Policies)
	}
}
