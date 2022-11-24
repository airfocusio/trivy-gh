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
	dryRun           bool
	issueCreateLimit int
	issueUpdateLimit int
	issuesCreated    int
	issuesUpdated    int
	ctx              context.Context
	githubClient     *github.Client
}

type Mitigation struct {
	Mitigation ConfigMitigation
	Policy     ConfigPolicy
}

type ProcessedUnfixedVulnerability struct {
	issueNumber   *int
	mitigations   []Mitigation
	report        types.Report
	result        types.Result
	vulnerability types.DetectedVulnerability
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

	allUnfixedVulnerabilities := []ProcessedUnfixedVulnerability{}
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
		unfixedVulnerabilities, err := s.ProcessUnfixedVulnerabilities(artifactNameShort, reports)
		unnest()

		if err != nil {
			return err
		}

		allUnfixedVulnerabilities = append(allUnfixedVulnerabilities, unfixedVulnerabilities...)
		for _, puv := range unfixedVulnerabilities {
			if puv.issueNumber != nil {
				unfixedIssueNumbers = append(unfixedIssueNumbers, *puv.issueNumber)
			}
		}
	}

	if _, err := s.ProcessFixedVulnerabilities("", unfixedIssueNumbers); err != nil {
		return err
	}

	if err := s.ProcessDashboard(allUnfixedVulnerabilities); err != nil {
		return err
	}

	return nil
}

func (s *Scan) ProcessUnfixedVulnerability(artifactNameShort string, report types.Report, res types.Result, vuln types.DetectedVulnerability) (*ProcessedUnfixedVulnerability, error) {
	policy := s.FindMatchingPolicy(report, res, vuln)
	mitigations := s.EvaluateMitigations(policy)

	// prepare general data
	id := fmt.Sprintf("%s/%s/%s", artifactNameShort, vuln.PkgName, vuln.VulnerabilityID)
	idFooter := fmt.Sprintf("trivy-gh-id=%s", id)
	title := vuln.Title
	if title == "" {
		title = StringAbbreviate(vuln.Description, 40)
	}
	if title == "" {
		title = vuln.VulnerabilityID
	}

	if policy != nil && policy.Ignore {
		s.logger.Debug.Printf("Found vulnerability %q [ignored]\n", title)
		return nil, nil
	}

	s.logger.Info.Printf("Found vulnerability %q\n", title)

	cvssVector, cvssScore, _ := FindVulnerabilityCVSSV3(vuln)
	unnest := s.logger.Nest()
	defer unnest()
	s.logger.Info.Printf("ID: %s\n", vuln.VulnerabilityID)
	s.logger.Info.Printf("Title: %s\n", title)
	s.logger.Info.Printf("Artifact: %s\n", report.ArtifactName)
	s.logger.Info.Printf("Package: %s\n", vuln.PkgName)
	if cvssVector != "" {
		s.logger.Info.Printf("CVSS: %s (%.1f)\n", cvssVector, cvssScore)
	}
	for _, m := range mitigations {
		text := StringSanitize(m.Mitigation.Label)
		if m.Policy.Comment != "" {
			text = text + ": " + StringSanitize(strings.ReplaceAll(m.Policy.Comment, "\n", " "))
		}
		s.logger.Info.Printf("Mitigation: %s\n", text)
	}

	// find existing issue
	existingIssuesSearchLabels := generateVulnerabilitySearchExistingLabels(artifactNameShort, vuln)
	existingIssuesSearchState := "all"
	existingIssues, existingIssuesRes, err := s.githubClient.Issues.ListByRepo(s.ctx, s.config.Github.IssueRepoOwner, s.config.Github.IssueRepoName, &github.IssueListByRepoOptions{
		Labels: existingIssuesSearchLabels,
		State:  existingIssuesSearchState,
		ListOptions: github.ListOptions{
			PerPage: 100, // TODO search all issues
		},
	})
	defer existingIssuesRes.Body.Close()
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
		mitigated := len(mitigations) > 0
		if mitigated {
			return &ProcessedUnfixedVulnerability{
				mitigations:   mitigations,
				report:        report,
				result:        res,
				vulnerability: vuln,
			}, nil
		}

		// create new issue
		body := s.RenderGithubIssueBody(report, res, vuln, "<!-- "+idFooter+" -->")
		labels := generateVulnerabilityLabels(artifactNameShort, vuln)
		state := "open"
		issue := github.IssueRequest{
			Title:  &title,
			Body:   &body,
			Labels: &labels,
			State:  &state,
		}

		if s.issueCreateLimit >= 0 && s.issuesCreated >= s.issueCreateLimit {
			s.logger.Info.Printf("Skipped creating issue [limit exceeded]\n")
			return &ProcessedUnfixedVulnerability{
				mitigations:   mitigations,
				report:        report,
				result:        res,
				vulnerability: vuln,
			}, nil
		} else if s.dryRun {
			s.logger.Info.Printf("Skipped creating issue [dry run]\n")
			return &ProcessedUnfixedVulnerability{
				mitigations:   mitigations,
				report:        report,
				result:        res,
				vulnerability: vuln,
			}, nil
		} else {
			createdIssue, createdIssueRes, err := s.githubClient.Issues.Create(s.ctx, s.config.Github.IssueRepoOwner, s.config.Github.IssueRepoName, &issue)
			defer createdIssueRes.Body.Close()
			if err != nil {
				return nil, err
			}
			s.logger.Info.Printf("Created issue #%d\n", *createdIssue.Number)
			s.issuesCreated = s.issuesCreated + 1
			return &ProcessedUnfixedVulnerability{
				issueNumber:   createdIssue.Number,
				mitigations:   mitigations,
				report:        report,
				result:        res,
				vulnerability: vuln,
			}, nil
		}
	} else {
		mitigated := len(mitigations) > 0

		// update existing issue if needed
		body := s.RenderGithubIssueBody(report, res, vuln, "<!-- "+idFooter+" -->")
		labels := generateVulnerabilityLabels(artifactNameShort, vuln)
		for _, l := range existingIssue.Labels {
			labelAlreadyExists := false
			for _, l2 := range labels {
				if l2 == *l.Name {
					labelAlreadyExists = true
					break
				}
			}
			if !labelAlreadyExists {
				labels = append(labels, *l.Name)
			}
		}
		state := "open"
		if mitigated {
			state = "closed"
		}
		issue := github.IssueRequest{
			Title:  &title,
			Body:   &body,
			Labels: &labels,
			State:  &state,
		}

		if !compareGithubIssues(*existingIssue, issue) {
			if s.issueUpdateLimit >= 0 && s.issuesUpdated >= s.issueUpdateLimit {
				s.logger.Info.Printf("Skipped updating issue #%d [limit exceeded]\n", *existingIssue.Number)
				return &ProcessedUnfixedVulnerability{
					issueNumber:   existingIssue.Number,
					mitigations:   mitigations,
					report:        report,
					result:        res,
					vulnerability: vuln,
				}, nil
			} else if s.dryRun {
				s.logger.Info.Printf("Skipped updating issue #%d [dry run]\n", *existingIssue.Number)
				return &ProcessedUnfixedVulnerability{
					issueNumber:   existingIssue.Number,
					mitigations:   mitigations,
					report:        report,
					result:        res,
					vulnerability: vuln,
				}, nil
			} else {
				_, updatedIssueRes, err := s.githubClient.Issues.Edit(s.ctx, s.config.Github.IssueRepoOwner, s.config.Github.IssueRepoName, *existingIssue.Number, &issue)
				defer updatedIssueRes.Body.Close()
				if err != nil {
					return nil, err
				}
				s.logger.Info.Printf("Updated issue #%d\n", *existingIssue.Number)
				s.issuesUpdated = s.issuesUpdated + 1
				return &ProcessedUnfixedVulnerability{
					issueNumber:   existingIssue.Number,
					mitigations:   mitigations,
					report:        report,
					result:        res,
					vulnerability: vuln,
				}, nil
			}
		} else {
			return &ProcessedUnfixedVulnerability{
				issueNumber:   existingIssue.Number,
				mitigations:   mitigations,
				report:        report,
				result:        res,
				vulnerability: vuln,
			}, nil
		}
	}
}

func (s *Scan) ProcessUnfixedVulnerabilities(artifactNameShort string, reports []*types.Report) ([]ProcessedUnfixedVulnerability, error) {
	processedVulnerabilities := []ProcessedUnfixedVulnerability{}
	for _, report := range reports {
		for _, res := range report.Results {
			for _, vuln := range res.Vulnerabilities {
				processVulnerability, err := s.ProcessUnfixedVulnerability(artifactNameShort, *report, res, vuln)
				if err != nil {
					return nil, err
				}
				if processVulnerability != nil {
					processedVulnerabilities = append(processedVulnerabilities, *processVulnerability)
				}
			}
		}
	}

	return processedVulnerabilities, nil
}

func (s *Scan) ProcessFixedVulnerabilities(artifactNameShort string, unfixedIssueNumbers []int) ([]int, error) {
	issueNumbers := []int{}

	// find all open issue that have not been seen unfixed
	openIssuesSearchLabels := generateVulnerabilitySearchOldLabels(artifactNameShort)
	openIssuesSearchState := "open"
	openIssues, openIssuesRes, err := s.githubClient.Issues.ListByRepo(s.ctx, s.config.Github.IssueRepoOwner, s.config.Github.IssueRepoName, &github.IssueListByRepoOptions{
		Labels: openIssuesSearchLabels,
		State:  openIssuesSearchState,
		ListOptions: github.ListOptions{
			PerPage: 100, // TODO search all issues
		},
	})
	defer openIssuesRes.Body.Close()
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
		s.logger.Info.Printf("Not found vulnerability %q anymore\n", *fixedIssue.Title)
		unnest := s.logger.Nest()

		state := "closed"
		issue := github.IssueRequest{
			State: &state,
		}
		if s.issueUpdateLimit >= 0 && s.issuesUpdated >= s.issueUpdateLimit {
			s.logger.Info.Printf("Skipped updating issue #%d [limit exceeded]\n", *fixedIssue.Number)
		} else if s.dryRun {
			s.logger.Info.Printf("Skipped updating issue #%d [dry run]\n", *fixedIssue.Number)
		} else {
			_, updatedIssueRes, err := s.githubClient.Issues.Edit(s.ctx, s.config.Github.IssueRepoOwner, s.config.Github.IssueRepoName, *fixedIssue.Number, &issue)
			defer updatedIssueRes.Body.Close()
			if err != nil {
				return nil, err
			}
			issueNumbers = append(issueNumbers, *fixedIssue.Number)
			s.logger.Info.Printf("Updated issue #%d\n", *fixedIssue.Number)
			s.issuesUpdated = s.issuesUpdated + 1
		}

		unnest()
	}

	return issueNumbers, nil
}

func (s *Scan) ProcessDashboard(allUnfixedVulnerabilities []ProcessedUnfixedVulnerability) error {
	footer := "trivy-gh-dashboard=true"

	existingIssueSearchState := "open"
	existingIssues, existingIssuesRes, err := s.githubClient.Issues.ListByRepo(s.ctx, s.config.Github.IssueRepoOwner, s.config.Github.IssueRepoName, &github.IssueListByRepoOptions{
		State: existingIssueSearchState,
		ListOptions: github.ListOptions{
			PerPage: 100, // TODO search all issues
		},
	})
	defer existingIssuesRes.Body.Close()
	if err != nil {
		return nil
	}
	var existingIssue *github.Issue
	for _, i := range existingIssues {
		if strings.Contains(*i.Body, footer) {
			existingIssue = i
			break
		}
	}

	title := "Security dashboard"
	body := s.RenderGithubDashboardIssueBody(allUnfixedVulnerabilities, "<!-- "+footer+" -->")
	state := "open"

	if existingIssue == nil {
		if s.dryRun {
			s.logger.Info.Printf("Skipped creating dashboard issue issue [dry run]\n")
		} else {
			createdIssue, createdIssueRes, err := s.githubClient.Issues.Create(s.ctx, s.config.Github.IssueRepoOwner, s.config.Github.IssueRepoName, &github.IssueRequest{
				Title: &title,
				Body:  &body,
				State: &state,
			})
			defer createdIssueRes.Body.Close()
			if err != nil {
				return err
			}
			s.logger.Info.Printf("Created dashboard issue #%d\n", *createdIssue.Number)
		}
	} else {
		if s.dryRun {
			s.logger.Info.Printf("Skipped updating dashboard issue #%d issue [dry run]\n", *existingIssue.Number)
		} else {
			updatedIssue, updatedIssueRes, err := s.githubClient.Issues.Edit(s.ctx, s.config.Github.IssueRepoOwner, s.config.Github.IssueRepoName, *existingIssue.Number, &github.IssueRequest{
				Title: &title,
				Body:  &body,
				State: &state,
			})
			defer updatedIssueRes.Body.Close()
			if err != nil {
				return err
			}
			s.logger.Info.Printf("Updated dashboard issue #%d\n", *updatedIssue.Number)
		}
	}

	return nil
}

func (s *Scan) FindMatchingPolicy(report types.Report, res types.Result, vuln types.DetectedVulnerability) *ConfigPolicy {
	for _, p := range s.config.Policies {
		if p.Match.IsMatch(report, res, vuln) {
			return &p
		}
	}
	return nil
}

func (s *Scan) EvaluateMitigations(policy *ConfigPolicy) []Mitigation {
	if policy == nil {
		return []Mitigation{}
	}

	result := []Mitigation{}
	for _, key := range policy.Mitigate {
		var mitigation *ConfigMitigation
		for _, m := range s.config.Mitigations {
			if m.Key == key {
				mitigation = &m
				break
			}
		}
		if mitigation == nil {
			s.logger.Info.Printf("Policy references unknown mitigation %s", key)
			continue
		}
		result = append(result, Mitigation{
			Mitigation: *mitigation,
			Policy:     *policy,
		})
	}
	return result
}

func (s *Scan) RenderGithubIssueBody(report types.Report, res types.Result, vuln types.DetectedVulnerability, footer string) string {
	cvssVector, cvssScore, _ := FindVulnerabilityCVSSV3(vuln)

	table := StringSanitize(fmt.Sprintf(`
| Key | Value
|---|---
| ID | %s
| CVSS Score | %s (%.1f)
| CVSS Vector | %s
| Artifact | %s
| Package | %s
| Installed Version | %s
| Fixed Version | %s
| Published | %v
`, vuln.VulnerabilityID, RenderCVSSScoreString(cvssScore), cvssScore, cvssVector, report.ArtifactName, vuln.PkgName, vuln.InstalledVersion, vuln.FixedVersion, vuln.PublishedDate))

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

	// cvssDetails := ""
	// if cvssMetric != nil {
	// 	lineTemplate := "%s: %s\n\n > %s"
	// 	lines := []string{
	// 		fmt.Sprintf(lineTemplate, AVName, AVValueNames[cvssMetric.AV], AVValueDescriptions[cvssMetric.AV]),
	// 		fmt.Sprintf(lineTemplate, ACName, ACValueNames[cvssMetric.AC], ACValueDescriptions[cvssMetric.AC]),
	// 		fmt.Sprintf(lineTemplate, PRName, PRValueNames[cvssMetric.PR], PRValueDescriptions[cvssMetric.PR]),
	// 		fmt.Sprintf(lineTemplate, UIName, UIValueNames[cvssMetric.UI], UIValueDescriptions[cvssMetric.UI]),
	// 		fmt.Sprintf(lineTemplate, SName, SValueNames[cvssMetric.S], SValueDescriptions[cvssMetric.S]),
	// 		fmt.Sprintf(lineTemplate, CName, CValueNames[cvssMetric.C], CValueDescriptions[cvssMetric.C]),
	// 		fmt.Sprintf(lineTemplate, IName, IValueNames[cvssMetric.I], IValueDescriptions[cvssMetric.I]),
	// 		fmt.Sprintf(lineTemplate, AName, AValueNames[cvssMetric.A], AValueDescriptions[cvssMetric.A]),
	// 	}
	// 	cvssDetails = fmt.Sprintf("<details>\n<summary>%s</summary>\n\n%s</details>", cvssVector, strings.Join(lines, "\n\n"))
	// }

	return strings.Join([]string{table, description, references, footer}, "\n\n")
}

func (s *Scan) RenderGithubDashboardIssueBody(allUnfixedVulnerabilities []ProcessedUnfixedVulnerability, footer string) string {
	rateLimited := ""
	rateLimitedTasks := []string{}
	for _, vuln := range allUnfixedVulnerabilities {
		if len(vuln.mitigations) == 0 && vuln.issueNumber == nil {
			_, cvssScore, _ := FindVulnerabilityCVSSV3(vuln.vulnerability)
			rateLimitedTasks = append(rateLimitedTasks, fmt.Sprintf("- [ ] [%s](%s) **%s** (%.1f) `%s`", vuln.vulnerability.VulnerabilityID, vuln.vulnerability.PrimaryURL, RenderCVSSScoreString(cvssScore), cvssScore, vuln.report.ArtifactName))
		}
	}
	if len(rateLimitedTasks) > 0 {
		rateLimited = strings.Join([]string{
			"### Rate limited",
			"The following issues have not been created yet, as the rate limit for issue creation has been exceeded. They will be created later.",
			strings.Join(rateLimitedTasks, "\n"),
		}, "\n\n")
	}

	mitigated := ""
	mitigatedTasks := []string{}
	for _, vuln := range allUnfixedVulnerabilities {
		if len(vuln.mitigations) > 0 {
			_, cvssScore, _ := FindVulnerabilityCVSSV3(vuln.vulnerability)
			mitigationTexts := []string{}
			for _, m := range vuln.mitigations {
				sanitizedLabel := strings.ReplaceAll(StringSanitize(m.Mitigation.Label), "\n", " ")
				if m.Policy.Comment == "" {
					mitigationTexts = append(mitigationTexts, sanitizedLabel)
				} else {
					sanitizedComment := strings.ReplaceAll(StringSanitize(m.Policy.Comment), "\n", " ")
					mitigationTexts = append(mitigationTexts, sanitizedLabel+": "+sanitizedComment)
				}
			}
			mitigatedTasks = append(mitigatedTasks, fmt.Sprintf("- [ ] [%s](%s) **%s** (%.1f) `%s` `%s`: %s", vuln.vulnerability.VulnerabilityID, vuln.vulnerability.PrimaryURL, RenderCVSSScoreString(cvssScore), cvssScore, vuln.report.ArtifactName, vuln.vulnerability.PkgName, strings.Join(mitigationTexts, ", ")))
		}
	}
	if len(mitigatedTasks) > 0 {
		mitigated = strings.Join([]string{
			"### Mitigated",
			"The following issues are still found, but have been marked as mitigated by some policy. They will stay here in this list until finally fixed.",
			strings.Join(mitigatedTasks, "\n"),
		}, "\n\n")
	}

	return strings.Join(StringsNonEmpty([]string{rateLimited, mitigated, footer}), "\n\n")
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
		result = append(result, s.extractArtifactsFromRawYaml(*fileYaml)...)
	}

	return result, nil
}

func (s *Scan) extractArtifactsFromRawYaml(node interface{}) []string {
	results := []string{}
	if m, ok := node.(map[string]interface{}); ok {
		for k, v := range m {
			if i, ok := v.(string); ok && k == "image" {
				results = append(results, i)
			} else {
				results = append(results, s.extractArtifactsFromRawYaml(v)...)
			}
		}
	}
	if a, ok := node.([]interface{}); ok {
		for _, e := range a {
			results = append(results, s.extractArtifactsFromRawYaml(e)...)
		}
	}
	return results
}

func artifactNameShortToLabel(artifactNameShort string) string {
	segments := strings.Split(artifactNameShort, "/")
	return StringAbbreviate(segments[len(segments)-1], 47)
}

func generateVulnerabilityLabels(artifactNameShort string, vuln types.DetectedVulnerability) []string {
	_, cvssScore, _ := FindVulnerabilityCVSSV3(vuln)
	return []string{
		"i:" + vuln.VulnerabilityID,
		"a:" + artifactNameShortToLabel(artifactNameShort),
		"s:" + RenderCVSSScoreString(cvssScore),
	}
}

func generateVulnerabilitySearchExistingLabels(artifactNameShort string, vuln types.DetectedVulnerability) []string {
	return []string{
		"i:" + vuln.VulnerabilityID,
		"a:" + artifactNameShortToLabel(artifactNameShort),
	}
}

func generateVulnerabilitySearchOldLabels(artifactNameShort string) []string {
	labels := []string{}
	if artifactNameShort != "" {
		labels = append(labels, "a:"+artifactNameShortToLabel(artifactNameShort))
	}
	return labels
}
