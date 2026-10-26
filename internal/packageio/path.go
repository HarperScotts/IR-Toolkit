package packageio

import (
	"fmt"
	"strings"
)

func asciiAlphanumeric(char byte) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
}

// ValidatePayloadPath is platform-independent and rejects, never sanitizes.
// It validates paths relative to case/, not arbitrary host evidence paths.
func ValidatePayloadPath(path string) error {
	invalid := func() error { return fmt.Errorf("%w: %q", ErrInvalidPath, path) }
	if path == "" || len("case/")+len(path) > 100 {
		return invalid()
	}
	components := strings.Split(path, "/")
	if len(components) > 8 {
		return invalid()
	}
	for _, component := range components {
		if len(component) == 0 || len(component) > 64 || !asciiAlphanumeric(component[0]) || strings.HasSuffix(component, ".") {
			return invalid()
		}
		for _, char := range []byte(component) {
			if !asciiAlphanumeric(char) && char != '_' && char != '-' && char != '.' {
				return invalid()
			}
		}
		stem := strings.ToUpper(strings.SplitN(component, ".", 2)[0])
		if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" ||
			(len(stem) == 4 && (stem[:3] == "COM" || stem[:3] == "LPT") && stem[3] >= '1' && stem[3] <= '9') {
			return invalid()
		}
	}
	return nil
}
