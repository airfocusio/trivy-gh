package internal

import (
	"regexp"
	"sort"
	"strings"

	"github.com/google/go-github/v48/github"
)

type GithubIssueTask struct {
	Done   bool
	Label  string
	Params map[string]string
}

var (
	githubIssueTaskRegex      = regexp.MustCompile(`^(?:\-|\*) \[(?P<done>[x ])\] (?P<paramsAndLabel>.*)$`)
	githubIssueTaskParamRegex = regexp.MustCompile(`^<!-- (?P<key>[^= ]+)(?:=(?P<value>[^ ]*))? --> (?P<rest>.*)$`)
)

func addGithubLabels(labels []*github.Label, labelNames ...string) []*github.Label {
	result := []*github.Label{}
	for _, l := range labels {
		name := *l.Name
		result = append(result, &github.Label{Name: &name})
	}
	for _, l := range labelNames {
		if l == "" {
			continue
		}
		duplicate := false
		for _, l2 := range result {
			if l == *l2.Name {
				duplicate = true
				break
			}
		}
		if !duplicate {
			name := l
			result = append(result, &github.Label{Name: &name})
		}
	}
	return result
}

func removeGithubLabels(labels []*github.Label, labelNames ...string) []*github.Label {
	result := []*github.Label{}
	for _, l := range labels {
		remove := false
		for _, l2 := range labelNames {
			if *l.Name == l2 {
				remove = true
				break
			}
		}
		if !remove {
			name := *l.Name
			result = append(result, &github.Label{Name: &name})
		}
	}
	return result
}

func filterGithubLabels(labels []*github.Label, fn func(string) bool) []*github.Label {
	result := []*github.Label{}
	for _, l := range labels {
		name := *l.Name
		if fn(name) {
			result = append(result, &github.Label{Name: &name})
		}
	}
	return result
}

func extractGithubIssueTasks(body string) []GithubIssueTask {
	result := []GithubIssueTask{}
	for _, line := range strings.Split(body, "\n") {
		taskMatch := githubIssueTaskRegex.FindStringSubmatch(line)
		if taskMatch != nil {
			done := taskMatch[1] == "x"
			paramsAndLabel := strings.Trim(taskMatch[2], " ")
			params := map[string]string{}
			for {
				paramMatch := githubIssueTaskParamRegex.FindStringSubmatch(paramsAndLabel)
				if paramMatch == nil {
					break
				}
				key := paramMatch[1]
				value := paramMatch[2]
				rest := paramMatch[3]
				params[key] = value
				paramsAndLabel = rest
			}
			if len(params) == 0 {
				params = nil
			}

			result = append(result, GithubIssueTask{
				Done:   done,
				Label:  paramsAndLabel,
				Params: params,
			})
		}
	}
	return result
}

func compareGithubIssues(i1 github.Issue, i2 github.IssueRequest) bool {
	i1Title := ""
	if i1.Title != nil {
		i1Title = *i1.Title
	}
	i2Title := ""
	if i2.Title != nil {
		i2Title = *i2.Title
	}
	cmpTitle := i1Title == i2Title

	i1Body := ""
	if i1.Body != nil {
		i1Body = *i1.Body
	}
	i2Body := ""
	if i2.Body != nil {
		i2Body = *i2.Body
	}
	cmpBody := i1Body == i2Body

	i1Labels := []string{}
	if i1.Labels != nil {
		for _, l := range i1.Labels {
			if l.Name != nil {
				i1Labels = append(i1Labels, *l.Name)
			}
		}
	}
	sort.Strings(i1Labels)
	i2Labels := []string{}
	if i2.Labels != nil {
		i2Labels = append(i2Labels, *i2.Labels...)
	}
	sort.Strings(i2Labels)
	cmpLabels := len(i1Labels) == len(i2Labels)
	if cmpLabels {
		for i := range i1Labels {
			if i1Labels[i] != i2Labels[i] {
				cmpLabels = false
				break
			}
		}
	}

	i1State := ""
	if i1.State != nil {
		i1State = *i1.State
	}
	i2State := ""
	if i2.State != nil {
		i2State = *i2.State
	}
	cmpState := i1State == i2State

	return cmpTitle && cmpBody && cmpLabels && cmpState
}
