package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestAnalysisVerifyReceiptAndNoFallback(t *testing.T) {
	for _, managed := range []bool{false, true} {
		root := t.TempDir()
		if managed {
			if err := os.WriteFile(filepath.Join(root, "analysis-run.json"), []byte(`{}`), 0600); err != nil {
				t.Fatal(err)
			}
		}
		var output bytes.Buffer
		cmd := newAnalysisVerifyCommand()
		cmd.SetOut(&output)
		cmd.SetErr(io.Discard)
		cmd.SetArgs([]string{root})
		err := cmd.Execute()
		if (err != nil) != managed {
			t.Fatal(managed, err)
		}
		// The JSON receipt stays on stdout; Cobra's diagnostic is separate stderr.
		var receipt map[string]any
		if err := json.Unmarshal(output.Bytes(), &receipt); err != nil {
			t.Fatalf("%s %v", output.String(), err)
		}
		want := "legacy_unmanaged"
		if managed {
			want = "rejected"
		}
		if receipt["status"] != want || receipt["domains_loaded"] != false || receipt["publication_attested"] != false {
			t.Fatal(receipt)
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		expected := 0
		if managed {
			expected = 1
		}
		if len(entries) != expected {
			t.Fatal("verifier wrote case files")
		}
	}
}
