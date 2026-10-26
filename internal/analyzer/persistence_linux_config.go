package analyzer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"path"
	"strings"
	"unicode/utf8"

	"ir-toolkit/internal/model"
)

const maxLinuxConfigRecords = 16384

func analyzeLinuxPersistenceConfigs(ctx context.Context, artifacts []model.LinuxPersistenceArtifact) ([]model.LinuxPersistenceConfig, []string) {
	if len(artifacts) == 0 {
		return nil, nil
	}
	warnings := []string{"Linux configuration records are file-local syntax only; activation/execution are unknown. Any separate systemd projection is conditional; no daemon validation, shell expansion, risk verdict or process correlation is performed."}
	var configs []model.LinuxPersistenceConfig
	remaining, inputBytes, incomplete := maxLinuxConfigRecords, 0, 0
	for index, artifact := range artifacts {
		if ctx.Err() != nil {
			warnings = append(warnings, "Linux configuration parsing cancelled; results are incomplete.")
			break
		}
		if index >= 4096 {
			warnings = append(warnings, "Linux configuration artifact limit; results are incomplete.")
			break
		}
		config := model.LinuxPersistenceConfig{Path: artifact.Path, Kind: artifact.Kind, SHA256: artifact.SHA256, Status: "skipped", Activation: "unknown"}
		byteLimit := len(artifact.Content) > 1<<20 || inputBytes+len(artifact.Content) > 32<<20
		if !byteLimit {
			inputBytes += len(artifact.Content)
		}
		skip := ""
		switch {
		case artifact.ReadError != "":
			skip = "Source read failed; content is not parsed."
		case artifact.LinkTarget != "" || strings.HasPrefix(artifact.Mode, "L"):
			skip = "Symbolic link evidence is not followed or interpreted as an effective configuration."
		case !strings.HasPrefix(artifact.Path, "/") || path.Clean(artifact.Path) != artifact.Path:
			skip = "Unsupported source path."
		case byteLimit:
			skip = "Configuration input byte limit."
		case remaining == 0:
			skip = "Configuration record limit."
		case !utf8.Valid(artifact.Content) || bytes.IndexByte(artifact.Content, 0) >= 0:
			skip = "Non-UTF-8 or NUL-containing source; inspect the original Base64 evidence."
		case bytes.Count(artifact.Content, []byte{'\n'}) > 65536:
			skip = "Configuration physical line limit."
		}
		if skip == "" {
			sum := sha256.Sum256(artifact.Content)
			if artifact.SHA256 == "" || artifact.SHA256 != fmt.Sprintf("%x", sum) {
				skip = "Missing or mismatched source SHA-256; parsing is not bound to verified collected bytes."
			}
		}
		if skip != "" {
			config.Warnings = []string{skip}
		} else {
			limit := min(4096, remaining)
			switch artifact.Kind {
			case "systemd":
				config.Format, config.Status = "systemd_directives", "observed_syntax"
				parseSystemdConfig(ctx, artifact.Content, &config, limit)
			case "cron":
				config.Format = cronSourceFormat(artifact.Path)
				if config.Format == "" {
					config.Warnings = []string{"Not a supported crontab source (periodic scripts and anacrontab remain opaque)."}
				} else {
					config.Status = "observed_syntax"
					parseCronConfig(ctx, artifact.Content, &config, limit)
				}
			default:
				config.Warnings = []string{"Unsupported Linux persistence kind."}
			}
			remaining -= len(config.Directives) + len(config.CronEntries)
		}
		if config.Status != "observed_syntax" {
			incomplete++
		}
		configs = append(configs, config)
	}
	if incomplete > 0 {
		warnings = append(warnings, fmt.Sprintf("%d Linux configuration candidates are partial/skipped; inspect per-file diagnostics. Empty parsed results do not establish absence of persistence.", incomplete))
	}
	return configs, warnings
}

func configDiagnostic(config *model.LinuxPersistenceConfig, line int, message string) {
	config.Status = "partial"
	// Bound diagnostic amplification independently of physical line count.
	if len(config.Warnings) < 64 {
		config.Warnings = append(config.Warnings, fmt.Sprintf("line %d: %s", line, message))
	} else if len(config.Warnings) == 64 {
		config.Warnings = append(config.Warnings, "Additional diagnostics omitted (limit 64).")
	}
}

func configIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for i, c := range []byte(value) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}

func parseSystemdConfig(ctx context.Context, data []byte, config *model.LinuxPersistenceConfig, limit int) {
	section, start := "", 0
	var pending strings.Builder
	for index, raw := range strings.Split(string(data), "\n") {
		line := index + 1
		if ctx.Err() != nil {
			configDiagnostic(config, line, "Parsing cancelled.")
			return
		}
		text := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if strings.HasPrefix(text, "#") || strings.HasPrefix(text, ";") || text == "" {
			continue
		}
		if start == 0 {
			start = line
		}
		continued := strings.HasSuffix(text, "\\")
		if continued {
			text = strings.TrimSuffix(text, "\\")
		}
		pending.WriteString(text)
		if continued {
			pending.WriteByte(' ')
			continue
		}
		text = strings.TrimSpace(pending.String())
		pending.Reset()
		first := start
		start = 0
		if strings.HasPrefix(text, "[") {
			section = ""
			if !strings.HasSuffix(text, "]") || strings.ContainsAny(text[1:len(text)-1], "[]") || strings.TrimSpace(text[1:len(text)-1]) == "" {
				configDiagnostic(config, first, "Malformed section; following assignments have no known section.")
				continue
			}
			section = text[1 : len(text)-1]
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || !configIdentifier(key) || section == "" {
			configDiagnostic(config, first, "Unrecognized directive or assignment outside a section.")
			continue
		}
		if len(config.Directives) >= limit {
			configDiagnostic(config, first, "Configuration record limit.")
			return
		}
		config.Directives = append(config.Directives, model.LinuxConfigDirective{Line: first, EndLine: line, Section: section, Key: key, Value: value, EmptyAssignment: value == ""})
	}
	if start != 0 {
		configDiagnostic(config, start, "Unterminated continuation; incomplete directive not interpreted.")
	}
}
