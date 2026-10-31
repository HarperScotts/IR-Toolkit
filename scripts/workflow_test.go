//go:build ignore

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestWorkflowSecurityContract(t *testing.T) {
	for _, file := range []string{"ci.yml", "release.yml"} {
		data, err := os.ReadFile(filepath.Join("..", ".github", "workflows", file))
		if err != nil {
			t.Fatal(err)
		}
		var workflow map[string]any
		if err := yaml.Unmarshal(data, &workflow); err != nil {
			t.Fatal(err)
		}
		permissions := workflow["permissions"].(map[string]any)
		if permissions["contents"] != "read" {
			t.Fatal("workflow default is not read-only")
		}
		if strings.Contains(string(data), "pull_request_target") || strings.Contains(string(data), "--clobber") {
			t.Fatal("unsafe workflow trigger/overwrite")
		}
		for _, job := range workflow["jobs"].(map[string]any) {
			for _, step := range job.(map[string]any)["steps"].([]any) {
				if uses, ok := step.(map[string]any)["uses"].(string); ok && !regexp.MustCompile(`^actions/[a-z-]+@[0-9a-f]{40}$`).MatchString(uses) {
					t.Fatal("action is not pinned", uses)
				}
			}
		}
		if file == "release.yml" && !strings.Contains(string(data), "--verify-tag --draft") {
			t.Fatal("release is not draft-only")
		}
	}
}
