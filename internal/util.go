package internal

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
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
