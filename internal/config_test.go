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

	bytes, err := os.ReadFile("./config_test.yaml")
	assert.NoError(t, err)

	c1, err := LoadConfig(bytes)
	if assert.NoError(t, err) {
		c2 := &Config{
			Github: ConfigGithub{
				Token:          "token",
				IssueRepoOwner: "owner",
				IssueRepoName:  "repo",
			},
			Files: []regexp.Regexp{
				*regexp.MustCompile(`f1$`),
				*regexp.MustCompile(`^f2`),
			},
			Mitigations: []ConfigMitigation{
				{
					Key:   "not-used",
					Label: "Not used",
				},
				{
					Key:   "no-public-networking",
					Label: "No public networking",
				},
			},
			Policies: []ConfigPolicy{
				{
					Comment: "Comment 1\n",
					Match: &AndPolicyMatcher{
						Inner: []PolicyMatcher{
							&IDPolicyMatcher{
								ID: []string{"CVE-0"},
							},
						},
					},
					Ignore: true,
				},
				{
					Comment: "Comment 2",
					Match: &AndPolicyMatcher{
						Inner: []PolicyMatcher{
							&ArtifactNameShortPolicyMatcher{
								ArtifactNameShort: []string{"debian"},
							},
						},
					},
					Mitigate: []string{"not-used"},
				},
				{
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
					Match: &AndPolicyMatcher{
						Inner: []PolicyMatcher{
							&ClassPolicyMatcher{
								Class: []string{"os-pkgs"},
							},
						},
					},
					Mitigate: []string{"not-used"},
				},
				{
					Match: &AndPolicyMatcher{
						Inner: []PolicyMatcher{
							&CVSSPolicyMatcher{
								CVSS: CVSSPolicyMatcherCVSS{
									AV: []string{"N", "L"},
									AC: []string{"H"},
									PR: []string{"H"},
									UI: []string{"N"},
									S:  []string{"C"},
									C:  []string{"H"},
									I:  []string{"H"},
									A:  []string{"H"},
								},
							},
						},
					},
					Mitigate: []string{"no-public-networking"},
				},
			},
		}
		assert.Equal(t, c2.Github, c1.Github)
		assert.Equal(t, c2.Files, c1.Files)
		assert.Equal(t, c2.Policies, c1.Policies)
	}
}
