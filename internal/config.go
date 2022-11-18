package internal

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/airfocusio/go-expandenv"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Github      ConfigGithub
	Files       []regexp.Regexp
	Mitigations []ConfigMitigation
	Policies    []ConfigPolicy
	CVSSSources []types.SourceID
}

type ConfigMitigation struct {
	Key         string `yaml:"key"`
	Label       string `yaml:"label"`
	AllowManual bool   `yaml:"allowManual"`
}

type ConfigPolicy struct {
	Comment string             `yaml:"comment"`
	Match   ConfigPolicyMatch  `yaml:"match"`
	Action  ConfigPolicyAction `yaml:"action"`
}

type ConfigPolicyMatch struct {
	ArtifactNameShort string                `yaml:"artifactNameShort"`
	PkgName           string                `yaml:"pkgName"`
	CVSS              ConfigPolicyMatchCVSS `yaml:"cvss"`
}

type ConfigPolicyMatchCVSS struct {
	ScoreLowerThan float64  `yaml:"scoreLowerThan"`
	AV             []string `yaml:"av"`
	AC             []string `yaml:"ac"`
	PR             []string `yaml:"pr"`
	UI             []string `yaml:"ui"`
	S              []string `yaml:"s"`
	C              []string `yaml:"c"`
	I              []string `yaml:"i"`
	A              []string `yaml:"a"`
}

type ConfigPolicyAction struct {
	Ignore   bool     `yaml:"ignore"`
	Mitigate []string `yaml:"mitigate"`
}

func (c *Config) UnmarshalYAML(value *yaml.Node) error {
	type rawConfig struct {
		Github      ConfigGithub       `yaml:"github"`
		Files       []string           `yaml:"files"`
		Mitigations []ConfigMitigation `yaml:"mitigations"`
		Policies    []ConfigPolicy     `yaml:"policies"`
		CVSSSources []string           `yaml:"cvssSources"`
	}
	raw := rawConfig{}
	err := value.Decode((*rawConfig)(&raw))
	if err != nil {
		return err
	}

	c.Github = raw.Github
	if len(raw.Files) > 0 {
		files := []regexp.Regexp{}
		for _, i := range raw.Files {
			regex, err := regexp.Compile(i)
			if err != nil {
				return fmt.Errorf("unable to parse file regexp: %w", err)
			}
			files = append(files, *regex)
		}
		c.Files = files
	}
	c.Mitigations = raw.Mitigations
	c.Policies = raw.Policies
	if len(raw.CVSSSources) > 0 {
		cvssSources := []types.SourceID{}
		for _, p := range raw.CVSSSources {
			cvssSources = append(cvssSources, types.SourceID(p))
		}
		c.CVSSSources = cvssSources
	} else {
		c.CVSSSources = []types.SourceID{"nvd", "redhat"}
	}
	return nil
}

type ConfigGithub struct {
	Token          string
	IssueRepoOwner string
	IssueRepoName  string
	LabelPrefix    string
}

func (c *ConfigGithub) UnmarshalYAML(value *yaml.Node) error {
	type rawConfigGithub struct {
		Token       string `yaml:"token"`
		IssueRepo   string `yaml:"issueRepo"`
		LabelPrefix string `yaml:"labelPrefix"`
	}
	raw := rawConfigGithub{}
	err := value.Decode((*rawConfigGithub)(&raw))
	if err != nil {
		return err
	}

	c.Token = raw.Token
	githubIssueRepoSegments := strings.SplitN(raw.IssueRepo, "/", 2)
	if len(githubIssueRepoSegments) != 2 {
		return fmt.Errorf("github issue repo is invalid")
	}
	c.IssueRepoOwner = githubIssueRepoSegments[0]
	c.IssueRepoName = githubIssueRepoSegments[1]
	c.LabelPrefix = raw.LabelPrefix
	return nil
}

func LoadConfig(bytesRaw []byte) (*Config, error) {
	var expansionTemp interface{}
	err := yaml.Unmarshal(bytesRaw, &expansionTemp)
	if err != nil {
		return nil, err
	}
	expansionTemp, err = expandenv.ExpandEnv(expansionTemp)
	if err != nil {
		return nil, err
	}
	bytes, err := yaml.Marshal(expansionTemp)
	if err != nil {
		return nil, err
	}
	config := Config{}
	err = yaml.Unmarshal(bytes, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}
