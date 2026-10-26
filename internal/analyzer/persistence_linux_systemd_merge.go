package analyzer

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"ir-toolkit/internal/model"
)

// Equal ranks for /lib and /usr/lib: collection does not prove their aliasing
// or the distribution's compiled layout. Same-tier collisions are ambiguous.
var systemdSystemProfile = []struct {
	root string
	rank int
}{
	{"/etc/systemd/system.control", 0}, {"/run/systemd/system.control", 1},
	{"/run/systemd/transient", 2}, {"/run/systemd/generator.early", 3},
	{"/etc/systemd/system", 4}, {"/etc/systemd/system.attached", 5},
	{"/run/systemd/system", 6}, {"/run/systemd/system.attached", 7},
	{"/run/systemd/generator", 8}, {"/usr/local/lib/systemd/system", 9},
	{"/usr/lib/systemd/system", 10}, {"/lib/systemd/system", 10},
	{"/run/systemd/generator.late", 11},
}

type systemdCandidate struct {
	artifact          model.LinuxPersistenceArtifact
	rank, specificity int
	typeWide          bool
	role              string
}

func mergeObservedSystemd(ctx context.Context, snapshot model.PersistenceSnapshot, configs []model.LinuxPersistenceConfig) ([]model.LinuxSystemdMerge, []string) {
	if len(snapshot.LinuxArtifacts) > 4096 || len(snapshot.LinuxSources) > 128 {
		return nil, []string{"Systemd merge input item limit; no projection emitted."}
	}
	inputBytes := 0
	for _, artifact := range snapshot.LinuxArtifacts {
		if ctx.Err() != nil {
			return nil, []string{"Systemd merge cancelled; no projection emitted."}
		}
		if len(artifact.Content) > 1<<20 || len(artifact.Content) > (32<<20)-inputBytes {
			return nil, []string{"Systemd merge input byte limit; no projection emitted."}
		}
		inputBytes += len(artifact.Content)
	}
	index := map[string][]systemdCandidate{}
	units := map[string]bool{}
	for _, artifact := range snapshot.LinuxArtifacts {
		if artifact.Kind != "systemd" {
			continue
		}
		if !strings.HasPrefix(artifact.Path, "/") || path.Clean(artifact.Path) != artifact.Path {
			return nil, []string{"Systemd merge source path is not normalized; no projection emitted."}
		}
		for _, source := range systemdSystemProfile {
			if !strings.HasPrefix(artifact.Path, source.root+"/") {
				continue
			}
			relative := strings.TrimPrefix(artifact.Path, source.root+"/")
			index[relative] = append(index[relative], systemdCandidate{artifact: artifact, rank: source.rank})
			parts := strings.Split(relative, "/")
			if len(parts) == 1 && strings.HasSuffix(parts[0], ".service") {
				units[parts[0]] = true
			}
			if len(parts) == 2 && strings.HasSuffix(parts[0], ".service.d") {
				name := strings.TrimSuffix(parts[0], ".d")
				// A hierarchy directory alone is not evidence of an actual
				// unit. Explicit base files still create their own view.
				parsed, err := parseObservedServiceName(name)
				if err != nil || !strings.HasSuffix(parsed.prefix, "-") {
					units[name] = true
				}
			}
			break
		}
	}
	if len(units) == 0 {
		return nil, nil
	}
	warnings := []string{"Systemd merge is a conditional observed system-service subset, not effective manager configuration. Custom/compiled load paths, aliases, escaped names, specifier expansion, runtime activation and execution remain unconfirmed; template definitions do not establish running instances."}
	coverage := ""
	for _, source := range systemdSystemProfile {
		var states []model.LinuxPersistenceSource
		for _, state := range snapshot.LinuxSources {
			if state.Path == source.root && state.Kind == "systemd" {
				states = append(states, state)
			}
		}
		if len(states) != 1 || states[0].Error != "" || states[0].Status != "observed" && states[0].Status != "missing" {
			coverage = "Source inventory missing, duplicated or incomplete: " + source.root
			break
		}
		if states[0].Status == "missing" {
			for _, candidates := range index {
				for _, candidate := range candidates {
					if strings.HasPrefix(candidate.artifact.Path, source.root+"/") {
						coverage = "Source marked missing but contains artifacts: " + source.root
						break
					}
				}
				if coverage != "" {
					break
				}
			}
		}
		if coverage != "" {
			break
		}
	}
	digest := model.LinuxPersistenceInputDigest(snapshot)
	parsed := map[string][]model.LinuxPersistenceConfig{}
	for _, config := range configs {
		if config.Kind == "systemd" {
			parsed[config.Path] = append(parsed[config.Path], config)
		}
	}
	names := make([]string, 0, len(units))
	for name := range units {
		names = append(names, name)
	}
	sort.Strings(names)
	var results []model.LinuxSystemdMerge
	remainingRecords, remainingBytes, remainingRefs := 16384, 32<<20, 16384
	for _, name := range names {
		if ctx.Err() != nil {
			warnings = append(warnings, "Systemd merge cancelled; results are incomplete.")
			break
		}
		if len(results) >= 512 {
			warnings = append(warnings, "Systemd merge unit limit (512); results are incomplete.")
			break
		}
		result := model.LinuxSystemdMerge{Unit: name, Scope: "system", Profile: "observed-system-service-v2", InputDigest: digest, Status: "blocked", Activation: "unknown"}
		if coverage != "" {
			result.Warnings = []string{coverage}
		} else {
			mergeOneSystemd(ctx, &result, index, parsed, &remainingRecords, &remainingBytes, &remainingRefs)
		}
		results = append(results, result)
	}
	blocked := 0
	for _, result := range results {
		if result.Status == "blocked" {
			blocked++
		}
	}
	if blocked > 0 {
		warnings = append(warnings, fmt.Sprintf("%d observed systemd service merges are blocked; no merged settings were emitted for them.", blocked))
	}
	return results, warnings
}

func mergeOneSystemd(ctx context.Context, result *model.LinuxSystemdMerge, index map[string][]systemdCandidate, parsed map[string][]model.LinuxPersistenceConfig, records, bytesLeft, refs *int) {
	name, err := parseObservedServiceName(result.Unit)
	if err != nil {
		result.Warnings = append(result.Warnings, err.Error())
		return
	}
	result.NameKind, result.Template, result.Instance = name.kind, name.template, name.instance
	names, err := observedSystemdDropinNames(result.Unit)
	if err != nil {
		result.Warnings = append(result.Warnings, err.Error())
		return
	}
	directories := map[string]int{"service.d": 0}
	for order, dropinName := range names {
		directories[dropinName+".d"] = len(names) - order
	}
	result.BaseLookup = "exact"
	baseCandidates := index[result.Unit]
	if name.kind == "template_definition" {
		result.BaseLookup = "template_definition"
	}
	if name.kind == "instance" && len(baseCandidates) == 0 {
		baseCandidates = index[name.template]
		result.BaseLookup = "template_fallback"
	}
	var candidates []systemdCandidate
	for _, candidate := range baseCandidates {
		candidate.role = "unit"
		candidates = append(candidates, candidate)
	}
	relatives := make([]string, 0, len(index))
	for relative := range index {
		relatives = append(relatives, relative)
	}
	sort.Strings(relatives)
	for _, relative := range relatives {
		entries := index[relative]
		parts := strings.Split(relative, "/")
		if _, relevant := directories[parts[0]]; len(parts) == 1 && relevant {
			result.Warnings = append(result.Warnings, "Drop-in directory is a non-traversed link or unreadable candidate: "+relative)
			return
		}
		specificity, relevant := directories[parts[0]]
		if len(parts) != 2 || !strings.HasSuffix(parts[1], ".conf") || !relevant {
			continue
		}
		for _, candidate := range entries {
			candidate.role = "dropin"
			candidate.specificity = specificity
			candidate.typeWide = parts[0] == "service.d"
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) > 128 || len(candidates) > *refs {
		result.Warnings = []string{"Systemd merge source-reference limit."}
		return
	}
	*refs -= len(candidates)
	// Select the unit and each distinct drop-in filename independently. For
	// Type-wide service.d is lowest priority. Other same-basename drop-ins
	// follow source rank, then upstream name expansion order within that root.
	// Different basenames are globally lexicographic.
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.role != b.role {
			return a.role == "unit"
		}
		if path.Base(a.artifact.Path) != path.Base(b.artifact.Path) {
			return path.Base(a.artifact.Path) < path.Base(b.artifact.Path)
		}
		if a.typeWide != b.typeWide {
			return !a.typeWide
		}
		if a.rank != b.rank {
			return a.rank < b.rank
		}
		if a.specificity != b.specificity {
			return a.specificity > b.specificity
		}
		return a.artifact.Path < b.artifact.Path
	})
	var selected []systemdCandidate
	ambiguous := false
	for first := 0; first < len(candidates); {
		last := first + 1
		for last < len(candidates) && candidates[last].role == candidates[first].role && path.Base(candidates[last].artifact.Path) == path.Base(candidates[first].artifact.Path) {
			last++
		}
		winner := candidates[first]
		collision := first+1 < last && candidates[first+1].rank == winner.rank && candidates[first+1].specificity == winner.specificity && candidates[first+1].typeWide == winner.typeWide
		for at := first; at < last; at++ {
			candidate := candidates[at]
			decision := "shadowed"
			if at == first {
				decision = "selected"
			}
			if collision && candidate.rank == winner.rank && candidate.specificity == winner.specificity && candidate.typeWide == winner.typeWide {
				decision = "ambiguous"
			}
			if !collision && at == first && winner.role == "dropin" && winner.artifact.LinkTarget == "/dev/null" && strings.HasPrefix(winner.artifact.Mode, "L") {
				decision = "masked_dropin"
			}
			result.Sources = append(result.Sources, model.LinuxSystemdMergeSource{Path: candidate.artifact.Path, SHA256: candidate.artifact.SHA256, LinkTarget: candidate.artifact.LinkTarget, Role: candidate.role, Decision: decision})
		}
		if collision {
			ambiguous = true
			result.Warnings = append(result.Warnings, "Same-tier source collision: "+path.Base(winner.artifact.Path))
		}
		selected = append(selected, winner)
		first = last
	}
	if ambiguous {
		return
	}
	if len(selected) == 0 || selected[0].role != "unit" {
		result.Warnings = append(result.Warnings, "No observed base unit; drop-ins alone cannot establish a configuration.")
		return
	}
	if selected[0].artifact.LinkTarget != "" || strings.HasPrefix(selected[0].artifact.Mode, "L") {
		result.Warnings = append(result.Warnings, "Selected unit is a link/mask/alias; no fallback to lower-priority content.")
		return
	}
	if len(selected[0].artifact.Content) == 0 {
		result.Warnings = append(result.Warnings, "Selected unit is empty/unreadable; no fallback to lower-priority content.")
		return
	}
	var directives []model.LinuxSystemdValue
	var declarations []model.LinuxConfigDirective
	for _, candidate := range selected {
		a := candidate.artifact
		if candidate.role == "dropin" && a.LinkTarget == "/dev/null" && a.ReadError == "" && strings.HasPrefix(a.Mode, "L") {
			continue
		}
		matches := parsed[a.Path]
		if a.ReadError != "" || a.LinkTarget != "" || strings.HasPrefix(a.Mode, "L") || len(matches) != 1 || matches[0].Status != "observed_syntax" || matches[0].SHA256 != a.SHA256 {
			result.Warnings = append(result.Warnings, "Selected source cannot be safely interpreted: "+a.Path)
			return
		}
		for _, declaration := range matches[0].Directives {
			if ctx.Err() != nil || *records <= 0 || len(declaration.Value) > *bytesLeft {
				result.Warnings = append(result.Warnings, "Systemd merge cancelled or directive/byte limit reached.")
				return
			}
			*records--
			*bytesLeft -= len(declaration.Value)
			directives = append(directives, model.LinuxSystemdValue{Value: declaration.Value, Path: a.Path, SHA256: a.SHA256, Line: declaration.Line, EndLine: declaration.EndLine})
			declarations = append(declarations, declaration)
		}
	}
	result.Settings = projectSystemdSettings(declarations, directives)
	result.Status = "observed_subset"
	result.Warnings = append(result.Warnings, "Only supported literal Service settings are projected; other directives remain in file-local syntax. Values are not expanded or validated; manager load path and runtime activation are unknown.")
}
