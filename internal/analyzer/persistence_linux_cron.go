package analyzer

import (
	"context"
	"path"
	"strconv"
	"strings"

	"ir-toolkit/internal/model"
)

func cronSourceFormat(source string) string {
	if source == "/etc/crontab" || path.Dir(source) == "/etc/cron.d" {
		return "system_crontab"
	}
	if path.Dir(source) == "/var/spool/cron" || path.Dir(source) == "/var/spool/cron/crontabs" {
		return "user_crontab"
	}
	return ""
}

// Only split the requested prefix. The shell command remainder must keep its
// quotes, inline comments, escapes, percent signs and internal whitespace.
func cronPrefix(text string, count int) ([]string, string, bool) {
	var fields []string
	for len(fields) < count {
		text = strings.TrimLeft(text, " \t")
		end := strings.IndexAny(text, " \t")
		if end < 0 {
			return nil, "", false
		}
		fields = append(fields, text[:end])
		text = text[end:]
	}
	text = strings.TrimLeft(text, " \t")
	return fields, text, text != ""
}

func parseCronConfig(ctx context.Context, data []byte, config *model.LinuxPersistenceConfig, limit int) {
	if len(data) > 0 && data[len(data)-1] != '\n' {
		configDiagnostic(config, 1, "Missing final newline; daemon acceptance is not established.")
	}
	for index, raw := range strings.Split(string(data), "\n") {
		line := index + 1
		if ctx.Err() != nil {
			configDiagnostic(config, line, "Parsing cancelled.")
			return
		}
		text := strings.TrimLeft(strings.TrimSuffix(raw, "\r"), " \t")
		if strings.TrimSpace(text) == "" || strings.HasPrefix(text, "#") {
			continue
		}
		if len(config.Directives)+len(config.CronEntries) >= limit {
			configDiagnostic(config, line, "Configuration record limit.")
			return
		}
		if key, value, ok := strings.Cut(text, "="); ok && configIdentifier(strings.TrimSpace(key)) {
			// Preserve trailing value whitespace and quoting. Cron environment
			// declarations are not shell assignments and must not be expanded.
			value = strings.TrimLeft(value, " \t")
			config.Directives = append(config.Directives, model.LinuxConfigDirective{Line: line, EndLine: line, Key: strings.TrimSpace(key), Value: value, EmptyAssignment: value == ""})
			continue
		}
		count := 5
		if strings.HasPrefix(text, "@") {
			count = 1
		}
		if config.Format == "system_crontab" {
			count++
		}
		fields, command, ok := cronPrefix(text, count)
		if !ok {
			configDiagnostic(config, line, "Missing schedule/user/command fields.")
			continue
		}
		scheduleFields := fields
		user, userSource := path.Base(config.Path), "spool_filename"
		if config.Format == "system_crontab" {
			user, userSource = fields[len(fields)-1], "system_field"
			scheduleFields = fields[:len(fields)-1]
		}
		if !validCronSchedule(scheduleFields) {
			configDiagnostic(config, line, "Invalid or unsupported schedule; no execution time inferred.")
			continue
		}
		config.CronEntries = append(config.CronEntries, model.LinuxCronEntry{Line: line, Schedule: strings.Join(scheduleFields, " "), CommandRaw: command, DeclaredUser: user, UserSource: userSource})
		if strings.Contains(command, "%") {
			configDiagnostic(config, line, "Command retains literal percent/escape syntax; cron stdin transformation is not interpreted.")
		}
	}
}

func validCronSchedule(fields []string) bool {
	if len(fields) == 1 {
		switch fields[0] {
		case "@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly":
			return true
		}
		return false
	}
	if len(fields) != 5 {
		return false
	}
	for i, field := range fields {
		minimum, maximum := []int{0, 0, 1, 1, 0}[i], []int{59, 23, 31, 12, 7}[i]
		value := func(text string) (int, bool) {
			n, err := strconv.Atoi(text)
			if err == nil {
				return n, n >= minimum && n <= maximum && text != "" && !strings.ContainsAny(text, "+-")
			}
			var names []string
			if i == 3 {
				names = []string{"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"}
			}
			if i == 4 {
				names = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}
			}
			for index, name := range names {
				if strings.EqualFold(name, text) {
					if i == 3 {
						index++
					}
					return index, true
				}
			}
			return 0, false
		}
		for _, item := range strings.Split(field, ",") {
			base, step, hasStep := strings.Cut(item, "/")
			if hasStep {
				n, err := strconv.ParseUint(step, 10, 32)
				if err != nil || n == 0 {
					return false
				}
			}
			if base == "*" {
				continue
			}
			first, last, isRange := strings.Cut(base, "-")
			left, ok := value(first)
			if !ok {
				return false
			}
			if isRange {
				right, ok := value(last)
				if !ok || left > right {
					return false
				}
			} else if hasStep {
				return false
			}
		}
	}
	return true
}
