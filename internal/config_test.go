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
			Mitigations: []ConfigPolicy{
				{
					Comment: "Comment 2",
					Match: &ArtifactNameShortPolicyMatcher{
						ArtifactNameShort: []string{"debian"},
					},
				},
				{
					Match: &PackageNamePolicyMatcher{
						PackageName: []string{"sh", "bash"},
					},
				},
				{
					Match: &ClassPolicyMatcher{
						Class: []string{"os-pkgs"},
					},
				},
				{
					Match: &CVSSPolicyMatcher{
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
				{
					Match: &NotPolicyMatcher{
						Not: &IDPolicyMatcher{
							ID: []string{"CVE-1"},
						},
					},
				},
				{
					Match: &AndPolicyMatcher{
						And: []PolicyMatcher{
							&IDPolicyMatcher{
								ID: []string{"CVE-2"},
							},
							&IDPolicyMatcher{
								ID: []string{"CVE-3"},
							},
						},
					},
				},
				{
					Match: &OrPolicyMatcher{
						Or: []PolicyMatcher{
							&IDPolicyMatcher{
								ID: []string{"CVE-4"},
							},
							&IDPolicyMatcher{
								ID: []string{"CVE-5"},
							},
						},
					},
				},
			},
			Ignores: []ConfigPolicy{
				{
					Comment: "Comment 1\n",
					Match: &IDPolicyMatcher{
						ID: []string{"CVE-0"},
					},
				},
			},
		}
		assert.Equal(t, c2.Github, c1.Github)
		assert.Equal(t, c2.Files, c1.Files)
		assert.Equal(t, c2.Mitigations, c1.Mitigations)
		assert.Equal(t, c2.Ignores, c1.Ignores)
	}
}
