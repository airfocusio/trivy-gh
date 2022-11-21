package internal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
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
	dryRun           bool
	issueCreateLimit int
	issueUpdateLimit int
	issuesCreated    int
	issuesUpdated    int
	ctx              context.Context
	githubClient     *github.Client
}

func NewScan(logger Logger, config Config, dir string, dryRun bool, issueCreateLimit int, issueUpdateLimit int) Scan {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: config.Github.Token},
	)
	tc := oauth2.NewClient(ctx, ts)
	return Scan{
		logger:           logger,
		config:           config,
		dir:              dir,
		dryRun:           dryRun,
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

	artifactGroups := map[string][]string{}
	for _, file := range files {
		as, err := s.ScrapeFile(file)
		if err != nil {
			return err
		}
		for _, a := range as {
			artifactNameShort := strings.SplitN(a, ":", 2)[0]
			if _, ok := artifactGroups[artifactNameShort]; !ok {
				artifactGroups[artifactNameShort] = []string{}
			}
			artifactGroups[artifactNameShort] = append(artifactGroups[artifactNameShort], a)
		}
	}
	for artifactNameShort := range artifactGroups {
		artifactGroups[artifactNameShort] = StringsUnique(artifactGroups[artifactNameShort])
		sort.Strings(artifactGroups[artifactNameShort])
	}

	unfixedIssueNumbers := []int{}
	for artifactNameShort, artifacts := range artifactGroups {
		s.logger.Info.Printf("Scanning artifact group %s ...\n", artifactNameShort)
		unnest := s.logger.Nest()

		reports := []*types.Report{}
		for _, artifactName := range artifacts {
			s.logger.Info.Printf("Scanning artifact %s ...\n", artifactName)
			report, err := TrivyImage(s.ctx, s.dir, artifactName)
			if err != nil {
				unnest()
				return err
			}
			reports = append(reports, report)
		}
		issueNumbers, err := s.ProcessUnfixedIssues(artifactNameShort, reports)
		if err != nil {
			unnest()
			return err
		}
		unfixedIssueNumbers = append(unfixedIssueNumbers, issueNumbers...)
		unnest()
	}

	if _, err := s.ProcessFixedIssues("", unfixedIssueNumbers); err != nil {
		return err
	}

	return nil
}

func (s *Scan) ProcessUnfixedIssue(artifactNameShort string, report types.Report, res types.Result, vuln types.DetectedVulnerability) (*int, error) {
	// prepare policies
	matchingPolicies := s.EvaluateMatchingPolicies(report, res, vuln)
	policyBasedMitigationTasks := s.EvaluatePolicyBasedMitigationTasks(matchingPolicies)
	policyBasedIgnores := []ConfigPolicy{}
	for _, p := range matchingPolicies {
		if p.Ignore {
			policyBasedIgnores = append(policyBasedIgnores, p)
		}
	}

	// prepare general data
	id := fmt.Sprintf("%s/%s/%s", artifactNameShort, vuln.PkgName, vuln.VulnerabilityID)
	idFooter := fmt.Sprintf("<!-- trivy-gh-id=%s -->", id)
	title := vuln.Title
	if title == "" {
		title = StringAbbreviate(vuln.Description, 40)
	}
	if title == "" {
		title = vuln.VulnerabilityID
	}

	logDetails := func(logger *log.Logger) {
		cvssVector, cvssScore, _ := FindVulnerabilityCVSSV3(vuln)
		logger.Printf("ID: %s\n", vuln.VulnerabilityID)
		logger.Printf("Title: %s\n", title)
		logger.Printf("Artifact: %s\n", report.ArtifactName)
		logger.Printf("Package: %s\n", vuln.PkgName)
		if cvssVector != "" {
			logger.Printf("CVSS: %s (%.1f)\n", cvssVector, cvssScore)
		}
		for _, m := range policyBasedMitigationTasks {
			text := StringSanitize(m.Mitigation.Label)
			if m.Policy.Comment != "" {
				text = text + ": " + StringSanitize(strings.ReplaceAll(m.Policy.Comment, "\n", " "))
			}
			logger.Printf("Mitigation: %s\n", text)
		}
		for _, p := range policyBasedIgnores {
			if p.Comment == "" {
				logger.Printf("Ignored\n")
			} else {
				text := StringSanitize(p.Comment)
				logger.Printf("Ignored: %s\n", text)
			}
		}
	}

	if len(policyBasedIgnores) > 0 {
		s.logger.Debug.Printf("Skipped creating/updating issue %q [ignored]\n", title)
		logDetails(s.logger.CloneNested().Debug)
		return nil, nil
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
		body := s.RenderGithubIssueBody(report, res, vuln, manualMitigationTasks, policyBasedMitigationTasks, idFooter)
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

		if s.issueCreateLimit >= 0 && s.issuesCreated >= s.issueCreateLimit {
			s.logger.Info.Printf("Skipped creating issue %q [limit exceeded]\n", *issue.Title)
			logDetails(s.logger.CloneNested().Info)
			return nil, nil
		} else if s.dryRun {
			s.logger.Info.Printf("Skipped creating issue %q [dry run]\n", *issue.Title)
			logDetails(s.logger.CloneNested().Info)
			return nil, nil
		} else {
			issueRes, _, err := s.githubClient.Issues.Create(s.ctx, s.config.Github.IssueRepoOwner, s.config.Github.IssueRepoName, &issue)
			if err != nil {
				return nil, err
			}
			s.logger.Info.Printf("Created issue %q (#%d)\n", *issue.Title, *issueRes.Number)
			logDetails(s.logger.CloneNested().Info)
			if *issueRes.State != state {
				_, _, err := s.githubClient.Issues.Edit(s.ctx, s.config.Github.IssueRepoOwner, s.config.Github.IssueRepoName, *issueRes.Number, &github.IssueRequest{
					State: &state,
				})
				if err != nil {
					return nil, err
				}
			}
			s.issuesCreated = s.issuesCreated + 1
			return issueRes.Number, nil
		}
	} else {
		existingIssueBody := ""
		if existingIssue.Body != nil {
			existingIssueBody = *existingIssue.Body
		}
		existingIssueTasks := extractGithubIssueTasks(existingIssueBody)
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
		body := s.RenderGithubIssueBody(report, res, vuln, manualMitigationTasks, policyBasedMitigationTasks, idFooter)
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
			if s.issueUpdateLimit >= 0 && s.issuesUpdated >= s.issueUpdateLimit {
				s.logger.Info.Printf("Skipped updating issue %q (#%d) [limit exceeded]\n", *issue.Title, *existingIssue.Number)
				logDetails(s.logger.CloneNested().Info)
				return existingIssue.Number, nil
			} else if s.dryRun {
				s.logger.Info.Printf("Skipped updating issue %q (#%d) [dry run]\n", *issue.Title, *existingIssue.Number)
				logDetails(s.logger.CloneNested().Info)
				return existingIssue.Number, nil
			} else {
				_, _, err := s.githubClient.Issues.Edit(s.ctx, s.config.Github.IssueRepoOwner, s.config.Github.IssueRepoName, *existingIssue.Number, &issue)
				if err != nil {
					return existingIssue.Number, err
				}
				s.logger.Info.Printf("Updated issue %q (#%d)\n", *issue.Title, *existingIssue.Number)
				logDetails(s.logger.CloneNested().Info)
				s.issuesUpdated = s.issuesUpdated + 1
				return existingIssue.Number, nil
			}
		} else {
			return existingIssue.Number, nil
		}
	}
}

func (s *Scan) ProcessUnfixedIssues(artifactNameShort string, reports []*types.Report) ([]int, error) {
	issueNumbers := []int{}
	for _, report := range reports {
		for _, res := range report.Results {
			for _, vuln := range res.Vulnerabilities {
				issueNumber, err := s.ProcessUnfixedIssue(artifactNameShort, *report, res, vuln)
				if err != nil {
					return nil, err
				}
				if issueNumber != nil {
					issueNumbers = append(issueNumbers, *issueNumber)
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
	for _, openIssue := range openIssues {
		unfixed := false
		for _, n := range unfixedIssueNumbers {
			if *openIssue.Number == n {
				unfixed = true
				break
			}
		}
		if !unfixed && openIssue.Body != nil && strings.Contains(*openIssue.Body, "trivy-gh-id") {
			fixedIssues = append(fixedIssues, openIssue)
		}
	}

	for _, fixedIssue := range fixedIssues {
		state := "closed"
		issue := github.IssueRequest{
			State: &state,
		}
		if s.issueUpdateLimit >= 0 && s.issuesUpdated >= s.issueUpdateLimit {
			s.logger.Info.Printf("Skipped updating issue %q (#%d) [limit exceeded]\n", *fixedIssue.Title, *fixedIssue.Number)
		} else if s.dryRun {
			s.logger.Info.Printf("Skipped updating issue %q (#%d) [dry run]\n", *fixedIssue.Title, *fixedIssue.Number)
		} else {
			_, _, err := s.githubClient.Issues.Edit(s.ctx, s.config.Github.IssueRepoOwner, s.config.Github.IssueRepoName, *fixedIssue.Number, &issue)
			if err != nil {
				return nil, err
			}
			issueNumbers = append(issueNumbers, *fixedIssue.Number)
			s.logger.Info.Printf("Updated issue %q (#%d)\n", *fixedIssue.Title, *fixedIssue.Number)
			s.issuesUpdated = s.issuesUpdated + 1
		}
	}

	return issueNumbers, nil
}

func (s *Scan) EvaluateMatchingPolicies(report types.Report, res types.Result, vuln types.DetectedVulnerability) []ConfigPolicy {
	result := []ConfigPolicy{}
	for _, p := range s.config.Policies {
		if p.Match.IsMatch(report, res, vuln) {
			result = append(result, p)
		}
	}
	return result
}

func (s *Scan) EvaluatePolicyBasedMitigationTasks(matchingPolicies []ConfigPolicy) []PolicyBasedMitigationTask {
	result := []PolicyBasedMitigationTask{}
	for _, p := range matchingPolicies {
		for _, key := range p.Mitigate {
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
			result = append(result, PolicyBasedMitigationTask{
				Mitigation: *mitigation,
				Policy:     p,
				Done:       true,
			})
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
	cvssVector, cvssScore, _ := FindVulnerabilityCVSSV3(vuln)

	table := StringSanitize(fmt.Sprintf(`
| Key | Value
|---|---
| ID | %s
| CVSS Score | %.1f
| CVSS Vector | %s
| Artifact | %s
| Package | %s
| Installed Version | %s
| Fixed Version | %s
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
	if vuln.PrimaryURL != "" {
		references = references + vuln.PrimaryURL + "\n"
	}
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
