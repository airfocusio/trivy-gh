package internal

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	trivydbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/goark/go-cvss/v3/metric"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"
)

func FileList(dir string, patterns []regexp.Regexp) ([]string, error) {
	files := []string{}
	err := filepath.Walk(dir, func(path string, f os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		pathRel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		pathRel = "/" + pathRel

		for _, i := range patterns {
			if i.Match([]byte(pathRel)) {
				files = append(files, path)
				return nil
			}
		}
		return nil
	})
	return files, err
}

func FileResolvePath(dir string, file string) string {
	if !filepath.IsAbs(file) {
		return filepath.Join(dir, file)
	}
	return file
}

func SlicesUnique[E comparable](slice []E) []E {
	keys := make(map[E]bool)
	list := []E{}
	for _, e := range slice {
		if _, value := keys[e]; !value {
			keys[e] = true
			list = append(list, e)
		}
	}
	return list
}

func SlicesFind[E any](slice []E, fn func(E) bool) *E {
	for _, e := range slice {
		if fn(e) {
			return &e
		}
	}
	return nil
}

type Group[K comparable, V any] struct {
	Key    K
	Values []V
}

func SlicesGroupByOrdered[K comparable, V any](slice []V, keyFn func(V) K) []Group[K, V] {
	result := []Group[K, V]{}
	for _, v := range slice {
		k := keyFn(v)
		idx := slices.IndexFunc(result, func(g Group[K, V]) bool {
			return g.Key == k
		})

		if idx < 0 {
			result = append(result, Group[K, V]{
				Key:    k,
				Values: []V{v},
			})
		} else {
			result[idx].Values = append(result[idx].Values, v)
		}
	}
	return result
}

func SlicesMap[I any, O any](slice []I, mapFn func(I) O) []O {
	result := []O{}
	for _, e := range slice {
		result = append(result, mapFn(e))
	}
	return result
}

func SlicesFlatMap[I any, O any](slice []I, mapFn func(I) []O) []O {
	result := []O{}
	for _, e := range slice {
		result = append(result, mapFn(e)...)
	}
	return result
}

func SlicesFilter[E any](slice []E, filterFn func(E) bool) []E {
	result := []E{}
	for _, v := range slice {
		if filterFn(v) {
			result = append(result, v)
		}
	}
	return result
}

func StringSanitize(s string) string {
	trimmed := strings.Trim(s, "\n ")
	lines := strings.Split(trimmed, "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " ")
	}
	return strings.Join(lines, "\n")
}

func StringSanitizeOneLine(s string) string {
	trimmed := strings.Trim(s, "\n ")
	lines := strings.Split(trimmed, "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " ")
	}
	return strings.Join(lines, " ")
}

func StringAbbreviate(str string, maxLength int) string {
	if len(str) < maxLength {
		return str
	}
	return str[0:maxLength] + "..."
}

func FindVulnerabilityCVSSV3(vuln types.DetectedVulnerability) (string, float64, *metric.Base) {
	cvss := trivydbtypes.CVSS{}
	for _, s := range cvssSources {
		if c, ok := vuln.CVSS[s]; ok {
			cvss = c
			break
		}
	}

	var cvssBaseMetric *metric.Base
	if cvss.V3Vector != "" {
		bm, err := metric.NewBase().Decode(cvss.V3Vector)
		if err == nil && bm.Ver != metric.VUnknown {
			cvssBaseMetric = bm
		}
	}

	return cvss.V3Vector, cvss.V3Score, cvssBaseMetric
}

type StringArray []string

func (sa *StringArray) UnmarshalYAML(value *yaml.Node) error {
	var multi []string
	err := value.Decode(&multi)
	if err != nil {
		var single string
		err := value.Decode(&single)
		if err != nil {
			return err
		}
		*sa = []string{single}
	} else {
		*sa = multi
	}
	return nil
}
