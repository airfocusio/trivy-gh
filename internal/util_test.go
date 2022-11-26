package internal

import (
	"os"
	"path"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestFileList(t *testing.T) {
	dir, err := os.MkdirTemp(os.TempDir(), "trivy-gh")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Mkdir(path.Join(dir, "folder"), 0o755); err != nil {
		panic(err)
	}
	if file, err := os.Create(path.Join(dir, "file1.yaml")); err != nil {
		panic(err)
	} else {
		file.Close()
	}
	if file, err := os.Create(path.Join(dir, "file2.yaml")); err != nil {
		panic(err)
	} else {
		file.Close()
	}
	if file, err := os.Create(path.Join(dir, "folder", "file3.yaml")); err != nil {
		panic(err)
	} else {
		file.Close()
	}

	t.Run("Empty", func(t *testing.T) {
		f, e := FileList(dir, []regexp.Regexp{})
		if assert.NoError(t, e) {
			assert.Equal(t, []string{}, f)
		}
	})

	t.Run("Single", func(t *testing.T) {
		f, e := FileList(dir, []regexp.Regexp{*regexp.MustCompile(`^/file\d\.yaml$`)})
		if assert.NoError(t, e) {
			assert.Equal(t, []string{
				path.Join(dir, "file1.yaml"),
				path.Join(dir, "file2.yaml"),
			}, f)
		}
	})

	t.Run("Multi", func(t *testing.T) {
		f, e := FileList(dir, []regexp.Regexp{*regexp.MustCompile(`file1\.yaml$`), *regexp.MustCompile(`file2\.yaml$`)})
		if assert.NoError(t, e) {
			assert.Equal(t, []string{
				path.Join(dir, "file1.yaml"),
				path.Join(dir, "file2.yaml"),
			}, f)
		}
	})

	t.Run("Subfolder", func(t *testing.T) {
		f, e := FileList(dir, []regexp.Regexp{*regexp.MustCompile(`\.yaml$`)})
		if assert.NoError(t, e) {
			assert.Equal(t, []string{
				path.Join(dir, "file1.yaml"),
				path.Join(dir, "file2.yaml"),
				path.Join(dir, "folder", "file3.yaml"),
			}, f)
		}
	})
}

func TestSlicesGroupByOrdered(t *testing.T) {
	assert.Equal(
		t,
		[]Group[int, int]{
			{Key: 0, Values: []int{0, 2, 4}},
			{Key: 1, Values: []int{1, 3, 5}},
		},
		SlicesGroupByOrdered([]int{0, 1, 2, 3, 4, 5}, func(i int) int {
			return i % 2
		}),
	)
	assert.Equal(
		t,
		[]Group[int, int]{
			{Key: 1, Values: []int{5, 3, 1}},
			{Key: 0, Values: []int{4, 2, 0}},
		},
		SlicesGroupByOrdered([]int{5, 4, 3, 2, 1, 0}, func(i int) int {
			return i % 2
		}),
	)
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
