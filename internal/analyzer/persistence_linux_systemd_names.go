package analyzer

import (
	"fmt"
	"strings"
)

type observedServiceName struct {
	prefix, instance, template, kind string
}

// This profile deliberately excludes escaped/non-ASCII names and additional @
// characters in instance names. No unescaping or specifier substitution occurs.
func parseObservedServiceName(name string) (observedServiceName, error) {
	var parsed observedServiceName
	if len(name) > 255 || !strings.HasSuffix(name, ".service") {
		return parsed, fmt.Errorf("unsupported service name length/type")
	}
	stem := strings.TrimSuffix(name, ".service")
	if strings.Count(stem, "@") > 1 {
		return parsed, fmt.Errorf("multiple @ instance syntax is outside this profile")
	}
	prefix, instance, hasAt := strings.Cut(stem, "@")
	if prefix == "" {
		return parsed, fmt.Errorf("service prefix is empty")
	}
	validPart := func(part string) bool {
		for _, c := range part {
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == ':' || c == '-' {
				continue
			}
			return false
		}
		return true
	}
	if !validPart(prefix) || !validPart(instance) {
		return parsed, fmt.Errorf("escaped or non-ASCII service name is outside this profile")
	}
	parsed = observedServiceName{prefix: prefix, instance: instance, kind: "plain"}
	if hasAt {
		parsed.template = prefix + "@.service"
		parsed.kind = "instance"
		if instance == "" {
			parsed.kind = "template_definition"
		}
	}
	return parsed, nil
}

// Names are emitted most-specific first, matching the upstream recursive
// expansion: exact name, template (for an instance), then dash-prefix chains.
// Prefixes are taken before @, not from dashes inside the instance string.
func observedSystemdDropinNames(name string) ([]string, error) {
	var names []string
	seen := map[string]bool{}
	var expand func(string) error
	expand = func(current string) error {
		if seen[current] {
			return nil
		}
		if len(names) >= 64 {
			return fmt.Errorf("systemd drop-in name expansion limit (64)")
		}
		parsed, err := parseObservedServiceName(current)
		if err != nil {
			return err
		}
		seen[current] = true
		names = append(names, current)
		if parsed.kind == "instance" {
			if err := expand(parsed.template); err != nil {
				return err
			}
		}
		prefix, chopped := parsed.prefix, false
		for {
			dash := strings.LastIndexByte(prefix, '-')
			if dash <= 0 {
				return nil
			}
			if dash < len(prefix)-1 || chopped {
				prefix = prefix[:dash+1]
				break
			}
			prefix = prefix[:dash]
			chopped = true
		}
		derived := prefix + ".service"
		if parsed.kind == "instance" {
			derived = prefix + "@" + parsed.instance + ".service"
		}
		return expand(derived)
	}
	if err := expand(name); err != nil {
		return nil, err
	}
	return names, nil
}
