package internal

import (
	"testing"

	"github.com/google/go-github/v48/github"
	"github.com/stretchr/testify/assert"
)

func TestAddGithubLabels(t *testing.T) {
	nodeID := "node"
	label1 := "l1"
	label2 := "l2"
	label3 := "l3"
	assert.Equal(t, []*github.Label{}, addGithubLabels([]*github.Label{}))
	assert.Equal(t, []*github.Label{{Name: &label1}}, addGithubLabels([]*github.Label{{Name: &label1, NodeID: &nodeID}}))
	assert.Equal(t, []*github.Label{{Name: &label1}}, addGithubLabels([]*github.Label{{Name: &label1, NodeID: &nodeID}}, label1))
	assert.Equal(t, []*github.Label{{Name: &label1}, {Name: &label2}}, addGithubLabels([]*github.Label{{Name: &label1, NodeID: &nodeID}}, label2))
	assert.Equal(t, []*github.Label{{Name: &label1}, {Name: &label2}, {Name: &label3}}, addGithubLabels([]*github.Label{{Name: &label1, NodeID: &nodeID}}, label2, label3))
}

func TestRemoveGithubLabels(t *testing.T) {
	nodeID := "node"
	label1 := "l1"
	label2 := "l2"
	label3 := "l3"
	assert.Equal(t, []*github.Label{}, removeGithubLabels([]*github.Label{}))
	assert.Equal(t, []*github.Label{{Name: &label1}}, removeGithubLabels([]*github.Label{{Name: &label1, NodeID: &nodeID}}))
	assert.Equal(t, []*github.Label{}, removeGithubLabels([]*github.Label{{Name: &label1, NodeID: &nodeID}}, label1))
	assert.Equal(t, []*github.Label{{Name: &label2}}, removeGithubLabels([]*github.Label{{Name: &label1, NodeID: &nodeID}, {Name: &label2, NodeID: &nodeID}}, label1))
	assert.Equal(t, []*github.Label{{Name: &label1}}, removeGithubLabels([]*github.Label{{Name: &label1, NodeID: &nodeID}, {Name: &label2, NodeID: &nodeID}}, label2))
	assert.Equal(t, []*github.Label{}, removeGithubLabels([]*github.Label{{Name: &label1, NodeID: &nodeID}, {Name: &label2, NodeID: &nodeID}}, label1, label2))
	assert.Equal(t, []*github.Label{}, removeGithubLabels([]*github.Label{{Name: &label1, NodeID: &nodeID}, {Name: &label2, NodeID: &nodeID}}, label1, label2, label3))
}

func TestFilterGithubLabels(t *testing.T) {
	nodeID := "node"
	label1 := "l1"
	label2 := "l2"
	assert.Equal(t, []*github.Label{{Name: &label1}}, filterGithubLabels([]*github.Label{{Name: &label1, NodeID: &nodeID}}, func(name string) bool {
		return true
	}))
	assert.Equal(t, []*github.Label{}, filterGithubLabels([]*github.Label{{Name: &label1, NodeID: &nodeID}}, func(name string) bool {
		return false
	}))
	assert.Equal(t, []*github.Label{{Name: &label1}}, filterGithubLabels([]*github.Label{{Name: &label1, NodeID: &nodeID}, {Name: &label2, NodeID: &nodeID}}, func(name string) bool {
		return name == label1
	}))
	assert.Equal(t, []*github.Label{{Name: &label2}}, filterGithubLabels([]*github.Label{{Name: &label1, NodeID: &nodeID}, {Name: &label2, NodeID: &nodeID}}, func(name string) bool {
		return name == label2
	}))
}

func TestExtractGithubIssueTasks(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		assert.Equal(t, []GithubIssueTask{}, extractGithubIssueTasks(""))
	})

	t.Run("Simple", func(t *testing.T) {
		assert.Equal(t, []GithubIssueTask{
			{Done: false, Label: "Foo"},
		}, extractGithubIssueTasks("- [ ] Foo"))
		assert.Equal(t, []GithubIssueTask{
			{Done: false, Label: "Foo"},
		}, extractGithubIssueTasks("* [ ] Foo"))
		assert.Equal(t, []GithubIssueTask{
			{Done: true, Label: "Foo"},
		}, extractGithubIssueTasks("- [x] Foo"))
		assert.Equal(t, []GithubIssueTask{
			{Done: true, Label: "Foo"},
		}, extractGithubIssueTasks("* [x] Foo"))
	})

	t.Run("Params", func(t *testing.T) {
		assert.Equal(t, []GithubIssueTask{
			{Done: false, Label: "Foo", Params: map[string]string{"k1": ""}},
		}, extractGithubIssueTasks("- [ ] <!-- k1 --> Foo"))
		assert.Equal(t, []GithubIssueTask{
			{Done: true, Label: "Foo", Params: map[string]string{"k1": "", "k2": ""}},
		}, extractGithubIssueTasks("- [x] <!-- k1 --> <!-- k2 --> Foo"))
		assert.Equal(t, []GithubIssueTask{
			{Done: false, Label: "Foo", Params: map[string]string{"k1": "v1"}},
		}, extractGithubIssueTasks("- [ ] <!-- k1=v1 --> Foo"))
		assert.Equal(t, []GithubIssueTask{
			{Done: true, Label: "Foo", Params: map[string]string{"k1": "v1", "k2": "v2"}},
		}, extractGithubIssueTasks("- [x] <!-- k1=v1 --> <!-- k2=v2 --> Foo"))
	})
}

func TestCompareGithubIssues(t *testing.T) {
	createIssue := func(title string, body string, labelStrs []string, state string) github.Issue {
		labels := []*github.Label{}
		for _, l := range labelStrs {
			name := l
			labels = append(labels, &github.Label{
				Name: &name,
			})
		}
		return github.Issue{
			Title:  &title,
			Body:   &body,
			Labels: labels,
			State:  &state,
		}
	}
	createIssueRequest := func(title string, body string, labelStrs []string, state string) github.IssueRequest {
		return github.IssueRequest{
			Title:  &title,
			Body:   &body,
			Labels: &labelStrs,
			State:  &state,
		}
	}
	assert.Equal(t, true, compareGithubIssues(github.Issue{}, github.IssueRequest{}))
	assert.Equal(t, true, compareGithubIssues(createIssue("t", "d", []string{"la", "lb"}, "open"), createIssueRequest("t", "d", []string{"la", "lb"}, "open")))
	assert.Equal(t, false, compareGithubIssues(createIssue("t1", "d", []string{"la", "lb"}, "open"), createIssueRequest("t2", "d", []string{"la", "lb"}, "open")))
	assert.Equal(t, false, compareGithubIssues(createIssue("t", "d1", []string{"la", "lb"}, "open"), createIssueRequest("t", "d2", []string{"la", "lb"}, "open")))
	assert.Equal(t, true, compareGithubIssues(createIssue("t", "d", []string{"lb", "la"}, "open"), createIssueRequest("t", "d", []string{"la", "lb"}, "open")))
	assert.Equal(t, false, compareGithubIssues(createIssue("t", "d", []string{"la"}, "open"), createIssueRequest("t", "d", []string{"la", "lb"}, "open")))
	assert.Equal(t, false, compareGithubIssues(createIssue("t", "d", []string{"la", "lb"}, "open"), createIssueRequest("t", "d", []string{"la"}, "open")))
	assert.Equal(t, false, compareGithubIssues(createIssue("t", "d", []string{"la1", "lb"}, "open"), createIssueRequest("t", "d", []string{"la2", "lb"}, "open")))
	assert.Equal(t, false, compareGithubIssues(createIssue("t", "d", []string{"la", "lb1"}, "open"), createIssueRequest("t", "d", []string{"la", "lb2"}, "open")))
	assert.Equal(t, false, compareGithubIssues(createIssue("t", "d1", []string{"la", "lb"}, "open"), createIssueRequest("t", "d2", []string{"la", "lb"}, "closed")))
}
