package packageio

import (
	"errors"
	"strings"
	"testing"
)

func TestValidatePayloadPath(t *testing.T) {
	for _, path := range []string{strings.Repeat("a", 48) + "/" + strings.Repeat("b", 46), strings.Repeat("a/", 7) + "b"} {
		if err := ValidatePayloadPath(path); err != nil {
			t.Errorf("exact path/depth limit %q: %v", path, err)
		}
	}
	for _, path := range []string{"manifest.json", "analysis/network_analysis.json", "raw/Event-1_v2.json", "a..b", "COM0.json", "com10.txt", strings.Repeat("a", 64), "a/" + strings.Repeat("b", 64)} {
		if err := ValidatePayloadPath(path); err != nil {
			t.Errorf("valid path %q: %v", path, err)
		}
	}
	invalid := []string{"", "/manifest.json", "../a", "a/../b", "./a", "a//b", "a/", "a\\b", "C:/a", "//server/share", "a:stream", "a b", "a.", "a\x00b", ".hidden", "_leading", "-leading", "证据.json", "COM1", "con.txt", "prn", "AuX.json", "NUL.log", "lpt9.txt", "COM1.foo.bar", strings.Repeat("a", 65), strings.Repeat("a/", 8) + "b", strings.Repeat("a", 48) + "/" + strings.Repeat("b", 47)}
	for _, path := range invalid {
		if err := ValidatePayloadPath(path); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("invalid path %q accepted: %v", path, err)
		}
	}
}

func FuzzValidatePayloadPath(f *testing.F) {
	for _, path := range []string{"manifest.json", "../a", "a\\b", "NUL.txt", "analysis/a.json"} {
		f.Add(path)
	}
	f.Fuzz(func(t *testing.T, path string) {
		if err := ValidatePayloadPath(path); err == nil {
			if len(path) > 95 || strings.ContainsAny(path, "\\:") || strings.HasPrefix(path, "/") {
				t.Fatalf("accepted unsafe path: %q", path)
			}
			for _, component := range strings.Split(path, "/") {
				if component == "" || component == "." || component == ".." {
					t.Fatalf("accepted unsafe component: %q", path)
				}
			}
		}
	})
}
