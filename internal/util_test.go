package internal

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFileList(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		f, e := FileList("../example", []regexp.Regexp{})
		if assert.NoError(t, e) {
			assert.Equal(t, []string{}, f)
		}
	})

	t.Run("Single", func(t *testing.T) {
		f, e := FileList("../example", []regexp.Regexp{*regexp.MustCompile(`/k8s/`)})
		if assert.NoError(t, e) {
			assert.Equal(t, []string{
				"../example/k8s/deployment1.yaml",
				"../example/k8s/deployment2.yaml",
			}, f)
		}
	})

	t.Run("Multi", func(t *testing.T) {
		f, e := FileList("../example", []regexp.Regexp{*regexp.MustCompile(`1\.yaml$`), *regexp.MustCompile(`2\.yaml$`)})
		if assert.NoError(t, e) {
			assert.Equal(t, []string{
				"../example/k8s/deployment1.yaml",
				"../example/k8s/deployment2.yaml",
			}, f)
		}
	})
}
