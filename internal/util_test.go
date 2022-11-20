package internal

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
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

func TestStringArrayUnmarshalYAML(t *testing.T) {
	type test struct {
		Value StringArray `yaml:"value"`
	}

	t1 := test{}
	if err := yaml.Unmarshal([]byte("value: foo"), &t1); assert.NoError(t, err) {
		assert.Equal(t, StringArray{"foo"}, t1.Value)
	}

	t2 := test{}
	if err := yaml.Unmarshal([]byte("value:\n-  foo\n-  bar\n"), &t2); assert.NoError(t, err) {
		assert.Equal(t, StringArray{"foo", "bar"}, t2.Value)
	}

	t3 := test{}
	if err := yaml.Unmarshal([]byte("value: 1"), &t3); assert.NoError(t, err) {
		assert.Equal(t, StringArray{"1"}, t3.Value)
	}

	t4 := test{}
	if err := yaml.Unmarshal([]byte("value: true"), &t4); assert.NoError(t, err) {
		assert.Equal(t, StringArray{"true"}, t4.Value)
	}

	t5 := test{}
	assert.ErrorContains(t, yaml.Unmarshal([]byte("value:\n  foo: bar\n"), &t5), "cannot unmarshal !!map into string")
}

func temporarySetenv(name string, value string) func() {
	originalValue := os.Getenv(name)
	os.Setenv(name, value)
	return func() {
		os.Setenv(name, originalValue)
	}
}
