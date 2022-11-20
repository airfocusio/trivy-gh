package internal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	trivydbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/google/go-github/v48/github"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

var cvssSources = []trivydbtypes.SourceID{"nvd", "redhat"}

type Scan struct {
	logger           Logger
	config           Config
	dir              string
	dry              bool
	issueCreateLimit int
	issueUpdateLimit int
	issuesCreated    int
	issuesUpdated    int
	ctx              context.Context
	githubClient     *github.Client
}

func NewScan(logger Logger, config Config, dir string, dry bool, issueCreateLimit int, issueUpdateLimit int) Scan {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: config.Github.Token},
	)
	tc := oauth2.NewClient(ctx, ts)
	return Scan{
		logger:           logger,
		config:           config,
		dir:              dir,
		dry:              dry,
		issueCreateLimit: issueCreateLimit,
		issueUpdateLimit: issueUpdateLimit,
		ctx:              ctx,
		githubClient:     github.NewClient(tc),
	}
}

func (s *Scan) Run() error {
	s.logger.Debug.Printf("Updating trivy database ...\n")
	if err := TrivyDownloadDb(s.ctx, s.dir); err != nil {
		return err
	}

	files, err := FileList(s.dir, s.config.Files)
	if err != nil {
		return nil
	}

	artifacts := map[string][]string{}
	for _, file := range files {
		as, err := s.ScrapeFile(file)
		if err != nil {
			return err
		}
		for _, a := range as {
			artifactNameShort := strings.SplitN(a, ":", 2)[0]
			if _, ok := artifacts[artifactNameShort]; !ok {
				artifacts[artifactNameShort] = []string{}
			}
			artifacts[artifactNameShort] = append(artifacts[artifactNameShort], a)
		}
	}
	for artifactNameShort := range artifacts {
		artifacts[artifactNameShort] = StringsUnique(artifacts[artifactNameShort])
		sort.Strings(artifacts[artifactNameShort])
	}

	unfixedIssueNumbers := []int{}
	for artifactNameShort, artifacts2 := range artifacts {
		s.logger.Info.Printf("Processing artifact %s ...\n", artifactNameShort)
		reports := []*types.Report{}
		for _, arti := range artifacts2 {
			report, err := s.ScanArtifact(arti)
			if err != nil {
				return err
			}
			reports = append(reports, report)
		}
		issueNumbers, err := s.ProcessUnfixedIssue(artifactNameShort, reports)
		if err != nil {
			return err
		}
		unfixedIssueNumbers = append(unfixedIssueNumbers, issueNumbers...)
	}

	if _, err := s.ProcessFixedIssues("", unfixedIssueNumbers); err != nil {
		return err
	}

	return nil
}

func (s *Scan) ProcessUnfixedIssue(artifactNameShort string, reports []*types.Report) ([]int, error) {
	issueNumbers := []int{}
	for _, report := range reports {
		for _, res := range report.Results {
		Vuln:
			for _, vuln := range res.Vulnerabilities {
				// prepare general data
				policies := s.FindMatchingPolicies(*report, res, vuln)
				for _, p := range policies {
					if p.Action.Ignore {
						s.logger.Debug.Printf("Ignoring %s %s %s\n", report.ArtifactName, vuln.PkgName, vuln.VulnerabilityID)
						continue Vuln
					}
				}
				id := fmt.Sprintf("%s/%s/%s", artifactNameShort, vuln.PkgName, vuln.VulnerabilityID)
				idFooter := fmt.Sprintf("<!-- id=%s -->", id)
				policyBasedMitigationTasks := []PolicyBasedMitigationTask{}
				for _, p := range policies {
					for _, key := range p.Action.Mitigate {
						var mitigation *ConfigMitigation
						for _, m := range s.config.Mitigations {
							if m.Key == key {
								mitigation = &m
								break
							}
						}
						if mitigation == nil {
							s.logger.Warn.Printf("Policy references unknown mitigation %s", key)
							continue
						}
						policyBasedMitigationTasks = append(policyBasedMitigationTasks, PolicyBasedMitigationTask{
							Mitigation: *mitigation,
							Policy:     p,
							Done:       true,
						})
					}
				}
				title := vuln.Title
				if title == "" {
					title = StringAbbreviate(vuln.Description, 40)
				}
				if title == "" {
					title = vuln.VulnerabilityID
				}

				// find existing issue
				existingIssuesSearchLabels := []string{
					vuln.VulnerabilityID,
					artifactNameShort,
				}
				existingIssuesSearchState := "all"
				existingIssues, _, err := s.githubClient.Issues.ListByRepo(s.ctx, s.config.Github.IssueRepoOwner, s.config.Github.IssueRepoName, &github.IssueListByRepoOptions{
					Labels: existingIssuesSearchLabels,
					State:  existingIssuesSearchState,
					ListOptions: github.ListOptions{
						PerPage: 100,
					},
				})
				if err != nil {
					return nil, err
				}
				var existingIssue *github.Issue
				for _, ei := range existingIssues {
					if ei.Body != nil && strings.Contains(*ei.Body, idFooter) {
						existingIssue = ei
						issueNumbers = append(issueNumbers, *ei.Number)
						break
					}
				}

				if existingIssue == nil {
					manualMitigationTasks := []ManualMitigationTask{}
					for _, m := range s.config.Mitigations {
						if !m.AllowManual {
							continue
						}
						manualMitigationTasks = append(manualMitigationTasks, ManualMitigationTask{
							Mitigation: m,
							Done:       false,
						})
					}

					// create new issue
					body := s.RenderGithubIssueBody(*report, res, vuln, manualMitigationTasks, policyBasedMitigationTasks, idFooter)
					labels := []string{
						vuln.VulnerabilityID,
						artifactNameShort,
						vuln.Severity,
					}
					state := "open"
					for _, p := range manualMitigationTasks {
						if p.Done {
							state = "closed"
							break
						}
					}
					for _, p := range policyBasedMitigationTasks {
						if p.Done {
							state = "closed"
							break
						}
					}
					issue := github.IssueRequest{
						Title:  &title,
						Body:   &body,
						Labels: &labels,
						State:  &state,
					}

					if s.dry {
						s.logger.Info.Printf("Skipped creating issue %s (dry run)\n", *issue.Title)
					} else if s.issueCreateLimit >= 0 && s.issuesCreated >= s.issueCreateLimit {
						s.logger.Info.Printf("Skipped creating issue %s (limit exceeded)\n", *issue.Title)
					} else {
						issueRes, _, err := s.githubClient.Issues.Create(s.ctx, s.config.Github.IssueRepoOwner, s.config.Github.IssueRepoName, &issue)
						if err != nil {
							return nil, err
						}
						issueNumbers = append(issueNumbers, *issueRes.Number)
						s.logger.Info.Printf("Created issue #%d %s\n", *issueRes.Number, *issue.Title)
						if *issueRes.State != state {
							_, _, err := s.githubClient.Issues.Edit(s.ctx, s.config.Github.IssueRepoOwner, s.config.Github.IssueRepoName, *issueRes.Number, &github.IssueRequest{
								State: &state,
							})
							if err != nil {
								return nil, err
							}
						}
					}
					s.issuesCreated = s.issuesCreated + 1
				} else {
					existingIssueTasks := extractGithubIssueTasks(*existingIssue.Body)
					manualMitigationTasks := []ManualMitigationTask{}
					for _, m := range s.config.Mitigations {
						if !m.AllowManual {
							continue
						}
						var task *GithubIssueTask
						for _, t := range existingIssueTasks {
							key, ok := t.Params["manual-mitigation"]
							if ok && key == m.Key {
								task = &t
								break
							}
						}
						manualMitigationTasks = append(manualMitigationTasks, ManualMitigationTask{
							Mitigation: m,
							Done:       task != nil && task.Done,
						})
					}

					// update existing issue if needed
					body := s.RenderGithubIssueBody(*report, res, vuln, manualMitigationTasks, policyBasedMitigationTasks, idFooter)
					labels := []string{
						vuln.VulnerabilityID,
						artifactNameShort,
						vuln.Severity,
					}
					state := "open"
					for _, p := range manualMitigationTasks {
						if p.Done {
							state = "closed"
							break
						}
					}
					for _, p := range policyBasedMitigationTasks {
						if p.Done {
							state = "closed"
							break
						}
					}
					issue := github.IssueRequest{
						Title:  &title,
						Body:   &body,
						Labels: &labels,
						State:  &state,
					}

					if !compareGithubIssues(*existingIssue, issue) {
						if s.dry {
							s.logger.Info.Printf("Skipped updating issue #%d %s (dry run)\n", *existingIssue.Number, *issue.Title)
						} else if s.issueUpdateLimit >= 0 && s.issuesUpdated >= s.issueUpdateLimit {
							s.logger.Info.Printf("Skipped updating issue #%d %s (limit exceeded)\n", *existingIssue.Number, *issue.Title)
						} else {
							_, _, err := s.githubClient.Issues.Edit(s.ctx, s.config.Github.IssueRepoOwner, s.config.Github.IssueRepoName, *existingIssue.Number, &issue)
							if err != nil {
								return nil, err
							}
							s.logger.Info.Printf("Updated issue #%d %s\n", *existingIssue.Number, *issue.Title)
						}
						s.issuesUpdated = s.issuesUpdated + 1
					}
				}
			}
		}
	}

	return issueNumbers, nil
}

func (s *Scan) ProcessFixedIssues(artifactNameShort string, unfixedIssueNumbers []int) ([]int, error) {
	issueNumbers := []int{}

	// find all open issue that have not been seen unfixed
	openIssuesSearchLabels := []string{}
	if artifactNameShort != "" {
		openIssuesSearchLabels = append(openIssuesSearchLabels, artifactNameShort)
	}
	openIssuesSearchState := "open"
	openIssues, _, err := s.githubClient.Issues.ListByRepo(s.ctx, s.config.Github.IssueRepoOwner, s.config.Github.IssueRepoName, &github.IssueListByRepoOptions{
		Labels: openIssuesSearchLabels,
		State:  openIssuesSearchState,
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	})
	if err != nil {
		return nil, err
	}
	fixedIssues := []*github.Issue{}
	for _, toBeClosedIssue := range openIssues {
		touched := false
		for _, n := range unfixedIssueNumbers {
			if *toBeClosedIssue.Number == n {
				touched = true
				break
			}
		}
		if !touched {
			fixedIssues = append(fixedIssues, toBeClosedIssue)
		}
	}

	for _, fixedIssue := range fixedIssues {
		state := "closed"
		issue := github.IssueRequest{
			State: &state,
		}
		if s.dry {
			s.logger.Info.Printf("Skipped updating issue #%d %s (dry run)\n", *fixedIssue.Number, *fixedIssue.Title)
		} else if s.issueUpdateLimit >= 0 && s.issuesUpdated >= s.issueUpdateLimit {
			s.logger.Info.Printf("Skipped updating issue #%d %s (limit exceeded)\n", *fixedIssue.Number, *fixedIssue.Title)
		} else {
			_, _, err := s.githubClient.Issues.Edit(s.ctx, s.config.Github.IssueRepoOwner, s.config.Github.IssueRepoName, *fixedIssue.Number, &issue)
			if err != nil {
				return nil, err
			}
			issueNumbers = append(issueNumbers, *fixedIssue.Number)
			s.logger.Info.Printf("Updated issue #%d %s\n", *fixedIssue.Number, *fixedIssue.Title)
		}
		s.issuesUpdated = s.issuesUpdated + 1
	}

	return issueNumbers, nil
}

func (s *Scan) FindMatchingPolicies(report types.Report, res types.Result, vuln types.DetectedVulnerability) []ConfigPolicy {
	result := []ConfigPolicy{}
	for _, p := range s.config.Policies {
		if p.Match.IsMatch(report, res, vuln) {
			result = append(result, p)
		}
	}
	return result
}

type RenderGithubIssueBodyOpts struct {
	ManualMitigations      RenderGithubIssueBodyOptsMitigations
	PolicyBasedMitigations RenderGithubIssueBodyOptsMitigations
}

type RenderGithubIssueBodyOptsMitigations struct {
	NotUsed            bool
	NoPublicNetworking bool
}

type ManualMitigationTask struct {
	Mitigation ConfigMitigation
	Done       bool
}

type PolicyBasedMitigationTask struct {
	Mitigation ConfigMitigation
	Policy     ConfigPolicy
	Done       bool
}

func (s *Scan) RenderGithubIssueBody(report types.Report, res types.Result, vuln types.DetectedVulnerability, manualMitigationTasks []ManualMitigationTask, policyBasedMitigationTasks []PolicyBasedMitigationTask, footer string) string {
	cvssVector, cvssScore := FindVulnerabilityCVSSV3(vuln)

	table := StringSanitize(fmt.Sprintf(`
| Key | Value
|---|---
| ID | %s
| CVSS | %.1f
| CVSS Vector | %s
| Artifact | %s
| Package | %s
| Installed version | %s
| Fixed version | %s
| Published | %v
`, vuln.VulnerabilityID, cvssScore, cvssVector, report.ArtifactName, vuln.PkgName, vuln.InstalledVersion, vuln.FixedVersion, vuln.PublishedDate))

	manualMitigations := "### Manual mitigations\n\n"
	for _, m := range manualMitigationTasks {
		manualMitigations = manualMitigations + renderGithubIssueTask(m.Done, fmt.Sprintf("<!-- manual-mitigation=%s --> %s", m.Mitigation.Key, m.Mitigation.Label)) + "\n"
	}
	manualMitigations = StringSanitize(manualMitigations)

	policyBasedMitigations := "### Policy-based mitigations\n\n"
	for _, m := range policyBasedMitigationTasks {
		policyBasedMitigations = policyBasedMitigations + renderGithubIssueTask(m.Done, fmt.Sprintf("<!-- policy-based-mitigation=%s --> %s", m.Mitigation.Key, m.Mitigation.Label))
		sanitizedComment := strings.ReplaceAll(StringSanitize(m.Policy.Comment), "\n", " ")
		if sanitizedComment != "" {
			policyBasedMitigations = policyBasedMitigations + ": " + sanitizedComment
		}
		policyBasedMitigations = policyBasedMitigations + "\n"
	}
	policyBasedMitigations = StringSanitize(policyBasedMitigations)

	description := StringSanitize(fmt.Sprintf(`
### Description

%s
`, vuln.Description))

	references := "### References\n\n"
	for _, url := range vuln.References {
		references = references + url + "\n"
	}
	references = StringSanitize(references)

	return strings.Join([]string{table, manualMitigations, policyBasedMitigations, description, references, footer}, "\n\n")
}

func (s *Scan) ScrapeFile(file string) ([]string, error) {
	s.logger.Debug.Printf("Scraping file %s ...\n", file)

	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("unable to read file %s: %w", file, err)
	}
	defer f.Close()

	result := []string{}
	d := yaml.NewDecoder(f)
	for {
		fileYaml := new(interface{})
		err := d.Decode(&fileYaml)
		if fileYaml == nil {
			continue
		}
		// break the loop in case of EOF
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("unable to parse file %s as yaml: %w", file, err)
		}
		result = append(result, extractArtifactsFromRawYaml(*fileYaml)...)
	}

	return result, nil
}

func (s *Scan) ScanArtifact(artifact string) (*types.Report, error) {
	s.logger.Info.Printf("Scanning artifact %s ...\n", artifact)

	report, err := TrivyImage(s.ctx, s.dir, artifact)
	if err != nil {
		return nil, err
	}

	counts := map[string]int{
		"UNKNOWN":  0,
		"LOW":      0,
		"MEDIUM":   0,
		"HIGH":     0,
		"CRITICAL": 0,
	}
	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			if i, ok := counts[vuln.Severity]; ok {
				counts[vuln.Severity] = i + 1
			} else {
				counts["UNKNOWN"] = counts["UNKNOWN"] + 1
			}
		}
	}

	s.logger.Debug.Printf("Found %d critical, %d high, %d medium, %d low, %d unknown vulnerabilities\n",
		counts["CRITICAL"],
		counts["HIGH"],
		counts["MEDIUM"],
		counts["LOW"],
		counts["UNKNOWN"],
	)

	return report, nil
}

func extractArtifactsFromRawYaml(node interface{}) []string {
	results := []string{}
	if m, ok := node.(map[string]interface{}); ok {
		for k, v := range m {
			if i, ok := v.(string); ok && k == "image" {
				results = append(results, i)
			} else {
				results = append(results, extractArtifactsFromRawYaml(v)...)
			}
		}
	}
	if a, ok := node.([]interface{}); ok {
		for _, e := range a {
			results = append(results, extractArtifactsFromRawYaml(e)...)
		}
	}
	return results
}
