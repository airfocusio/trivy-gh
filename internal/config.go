package internal

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/airfocusio/go-expandenv"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Github      ConfigGithub
	Files       []regexp.Regexp
	Mitigations []ConfigMitigation
	Policies    []ConfigPolicy
}

type ConfigMitigation struct {
	Key   string `yaml:"key"`
	Label string `yaml:"label"`
}

type ConfigPolicy struct {
	Comment  string        `yaml:"comment"`
	Match    PolicyMatcher `yaml:"matchers"`
	Ignore   bool          `yaml:"ignore"`
	Mitigate StringArray   `yaml:"mitigate"`
}

func (c *ConfigPolicy) UnmarshalYAML(value *yaml.Node) error {
	type rawConfigPolicy struct {
		Comment  string        `yaml:"comment"`
		Match    []interface{} `yaml:"matchers"`
		Ignore   bool          `yaml:"ignore"`
		Mitigate StringArray   `yaml:"mitigate"`
	}
	raw := rawConfigPolicy{}
	err := value.Decode((*rawConfigPolicy)(&raw))
	if err != nil {
		return err
	}
	c.Comment = raw.Comment
	matchers := []PolicyMatcher{}
	for _, r := range raw.Match {
		node := yaml.Node{}
		if err := node.Encode(r); err != nil {
			return err
		}
		if pm, err := PolicyMatcherUnmarshalYAML(&node); err != nil {
			return err
		} else {
			matchers = append(matchers, pm)
		}
	}
	c.Match = &AndPolicyMatcher{Inner: matchers}
	c.Ignore = raw.Ignore
	c.Mitigate = raw.Mitigate
	return nil
}

func (c *Config) UnmarshalYAML(value *yaml.Node) error {
	type rawConfig struct {
		Github      ConfigGithub       `yaml:"github"`
		Files       StringArray        `yaml:"files"`
		Mitigations []ConfigMitigation `yaml:"mitigations"`
		Policies    []ConfigPolicy     `yaml:"policies"`
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
	return nil
}

type ConfigGithub struct {
	Token          string
	IssueRepoOwner string
	IssueRepoName  string
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
