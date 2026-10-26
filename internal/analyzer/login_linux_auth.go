package analyzer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"ir-toolkit/internal/model"
)

// A deliberately narrow OpenSSH auth_log message with a syslog envelope.
// Neither arbitrary PAM text nor quoted/injected occurrences become records.
var linuxSSHAuthentication = regexp.MustCompile(`^([A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}|[0-9]{4}-[0-9]{2}-[0-9]{2}T[^ \t]+) +([^ \t]+) +(sshd(?:-session)?)(?:\[([0-9]+)\])?: (Accepted|Failed) ([^ \t]+) for (invalid user )?([^ \t]+) from ([^ \t]+) port ([0-9]+) ssh2(?::.*)?$`)

func analyzeLinuxLogin(ctx context.Context, artifacts []model.LinuxLoginArtifact) ([]model.LinuxLoginRecord, []model.LinuxLoginParseSource, *model.LinuxLoginStatistics, []string) {
	if len(artifacts) == 0 {
		return nil, nil, nil, nil
	}
	warnings := []string{"Linux login analysis covers log-reported OpenSSH Accepted/Failed messages only, not complete sessions, unique attempts, current logins, privilege or process identity. Other sources/formats remain uncovered; no Windows IDs, process links, findings or timeline events are synthesized.", "Traditional syslog lacks year/timezone and retains unknown time. Native Linux records are not filtered by collection windows; raw and parsed counts may include outside-window history. Log text and hashes are not authenticity proofs."}
	var records []model.LinuxLoginRecord
	var sources []model.LinuxLoginParseSource
	stats := &model.LinuxLoginStatistics{}
	if len(artifacts) > 16 {
		return nil, nil, stats, append(warnings, "Linux login source limit; no records parsed.")
	}
	pathCounts := map[string]int{}
	for _, artifact := range artifacts {
		pathCounts[artifact.Path]++
	}
	usedBytes := 0
	for index, artifact := range artifacts {
		if ctx.Err() != nil {
			warnings = append(warnings, "Linux login parsing cancelled; results incomplete.")
			break
		}
		if index >= 16 {
			warnings = append(warnings, "Linux login source limit; results incomplete.")
			break
		}
		source := model.LinuxLoginParseSource{Path: artifact.Path, SHA256: artifact.SHA256, Status: "skipped"}
		byteLimit := len(artifact.Content) > 8<<20 || len(artifact.Content) > (24<<20)-usedBytes
		if !byteLimit {
			usedBytes += len(artifact.Content)
		}
		skip := ""
		switch {
		case pathCounts[artifact.Path] != 1:
			skip = "Duplicate source path; ambiguous input is not parsed."
		case artifact.Kind != "auth_log":
			skip = "Opaque accounting source; binary layout/current session/history reconstruction not implemented."
		case artifact.Path != "/var/log/auth.log" && artifact.Path != "/var/log/auth.log.1" && artifact.Path != "/var/log/secure" && artifact.Path != "/var/log/secure.1":
			skip = "Unsupported authentication log source."
		case artifact.Status != "observed" || artifact.ReadError != "" || artifact.LinkTarget != "" || strings.HasPrefix(artifact.Mode, "L"):
			skip = "Source missing, unreadable, changed, incomplete or a non-followed link."
		case byteLimit:
			skip = "Linux login input byte limit."
		case !utf8.Valid(artifact.Content) || bytes.IndexByte(artifact.Content, 0) >= 0:
			skip = "Non-UTF-8/NUL source; inspect original Base64 evidence."
		case len(records) >= 16384:
			skip = "Linux login record limit."
		}
		if skip == "" {
			sum := sha256.Sum256(artifact.Content)
			if artifact.SHA256 != "" && artifact.SHA256 == fmt.Sprintf("%x", sum) {
				source.Status = "observed_subset"
				parseLinuxSSHLog(ctx, artifact, &source, &records)
			} else {
				skip = "Missing/mismatched source SHA-256; no records parsed."
			}
		}
		if skip != "" {
			source.Warnings = append(source.Warnings, skip)
		}
		if source.Status != "observed_subset" {
			warnings = append(warnings, "Linux login source incomplete/opaque: "+source.Path+" ("+source.Status+").")
		}
		sources = append(sources, source)
	}
	for _, record := range records {
		stats.RecordCount++
		if record.Outcome == "accepted" {
			stats.ReportedAccepted++
		} else {
			stats.ReportedFailed++
		}
		if record.Timestamp.IsZero() {
			stats.UnknownTimeCount++
		}
	}
	return records, sources, stats, warnings
}

func linuxLoginDiagnostic(source *model.LinuxLoginParseSource, line int, message string) {
	source.Status = "partial"
	if len(source.Warnings) < 32 {
		source.Warnings = append(source.Warnings, fmt.Sprintf("line %d: %s", line, message))
	} else if len(source.Warnings) == 32 {
		source.Warnings = append(source.Warnings, "Further diagnostics omitted (limit 32).")
	}
}

func parseLinuxSSHLog(ctx context.Context, artifact model.LinuxLoginArtifact, source *model.LinuxLoginParseSource, records *[]model.LinuxLoginRecord) {
	content := artifact.Content
	if len(content) > 0 && content[len(content)-1] != '\n' {
		end := bytes.LastIndexByte(content, '\n')
		content = content[:end+1]
		linuxLoginDiagnostic(source, bytes.Count(content, []byte{'\n'})+1, "Unterminated final fragment retained only as raw evidence; not parsed.")
	}
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	line := 0
	for scanner.Scan() {
		line++
		if ctx.Err() != nil {
			linuxLoginDiagnostic(source, line, "Parsing cancelled.")
			return
		}
		if line > 131072 || len(*records) >= 16384 {
			linuxLoginDiagnostic(source, line, "Physical line/record limit; remaining input not parsed.")
			return
		}
		text := strings.TrimSuffix(scanner.Text(), "\r")
		match := linuxSSHAuthentication.FindStringSubmatch(text)
		if match == nil {
			source.IgnoredLines++
			continue
		}
		ip, err := netip.ParseAddr(match[9])
		port, portErr := strconv.ParseUint(match[10], 10, 16)
		if err != nil || portErr != nil || port == 0 {
			linuxLoginDiagnostic(source, line, "Invalid literal peer address/port; matching log claim not normalized.")
			continue
		}
		timestamp, timeErr := time.Parse(time.RFC3339Nano, match[1])
		basis := "explicit_offset"
		if timeErr != nil {
			timestamp = time.Time{}
			basis = "unknown"
			if strings.Contains(match[1], "T") {
				linuxLoginDiagnostic(source, line, "Invalid or offset-free timestamp retained as unknown time.")
			}
		}
		sum := sha256.Sum256([]byte(artifact.Path + "\x00" + artifact.SHA256 + "\x00" + strconv.Itoa(line)))
		record := model.LinuxLoginRecord{ID: fmt.Sprintf("linux-login:%x", sum), SourcePath: artifact.Path, SourceSHA256: artifact.SHA256, Line: line, RawLine: text, Timestamp: timestamp, TimestampRaw: match[1], TimeBasis: basis, ReportedHost: match[2], Program: match[3], ReportedPID: match[4], Outcome: strings.ToLower(match[5]), Method: match[6], InvalidUserReported: match[7] != "", User: match[8], SourceIP: ip.String(), SourcePort: uint32(port)}
		*records = append(*records, record)
		source.RecordCount++
	}
	if err := scanner.Err(); err != nil {
		linuxLoginDiagnostic(source, line+1, "Line read limit/error: "+err.Error())
	}
}
