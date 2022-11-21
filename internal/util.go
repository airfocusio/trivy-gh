package internal

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	trivydbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/goark/go-cvss/v3/metric"
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

func StringsContain(strSlice []string, str string) bool {
	for _, s := range strSlice {
		if s == str {
			return true
		}
	}
	return false
}

func StringsUnique(strSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range strSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func StringSanitize(s string) string {
	trimmed := strings.Trim(s, "\n ")
	lines := strings.Split(trimmed, "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " ")
	}
	return strings.Join(lines, "\n")
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
