package analysiscommit

import "strings"

// This codec's v1 paths use the existing offline USTAR-compatible subset;
// keep it backend-independent so package readers can consume this codec later.
func validPath(path string) bool {
	if path == "" || len(path) > 95 {
		return false
	}
	parts := strings.Split(path, "/")
	if len(parts) > 8 {
		return false
	}
	alnum := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' }
	for _, part := range parts {
		if len(part) == 0 || len(part) > 64 || !alnum(part[0]) || strings.HasSuffix(part, ".") {
			return false
		}
		for _, c := range []byte(part) {
			if !alnum(c) && c != '_' && c != '-' && c != '.' {
				return false
			}
		}
		stem := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || len(stem) == 4 && (stem[:3] == "COM" || stem[:3] == "LPT") && stem[3] >= '1' && stem[3] <= '9' {
			return false
		}
	}
	return true
}

func validateFiles(list []File, limits Limits) (map[string]File, error) {
	if len(list) == 0 {
		return nil, ErrInvalid
	}
	if len(list) > limits.FileCount {
		return nil, ErrLimit
	}
	files := make(map[string]File, len(list))
	aliases := map[string]string{}
	dirs := map[string]bool{}
	var total int64
	for i, file := range list {
		// These names are interpreted specially even on case-insensitive hosts.
		// The commit file is never inventoried; alternate spellings must not
		// smuggle a conflicting marker or an allegedly absent IOC input.
		foldedPath := strings.ToLower(file.Path)
		if strings.EqualFold(file.Path, CommitPath) ||
			strings.EqualFold(file.Path, RunPath) && file.Path != RunPath ||
			strings.EqualFold(file.Path, IOCPath) && file.Path != IOCPath ||
			strings.HasPrefix(foldedPath, CommitPath+"/") ||
			strings.HasPrefix(foldedPath, RunPath+"/") ||
			strings.HasPrefix(foldedPath, IOCPath+"/") {
			return nil, ErrInvalid
		}
		if !validPath(file.Path) || i > 0 && list[i-1].Path >= file.Path || file.Size < 0 || !lowerHex(file.SHA256, 64) {
			return nil, ErrInvalid
		}
		if file.Size > limits.FileBytes || file.Size > limits.PayloadBytes-total {
			return nil, ErrLimit
		}
		total += file.Size
		parts := strings.Split(file.Path, "/")
		for n := range parts {
			prefix := strings.Join(parts[:n+1], "/")
			folded := strings.ToLower(prefix)
			if original, ok := aliases[folded]; ok && original != prefix {
				return nil, ErrInvalid
			}
			aliases[folded] = prefix
			if n < len(parts)-1 {
				if _, exists := files[prefix]; exists {
					return nil, ErrInvalid
				}
				dirs[prefix] = true
			} else if dirs[prefix] {
				return nil, ErrInvalid
			}
		}
		files[file.Path] = file
	}
	return files, nil
}
