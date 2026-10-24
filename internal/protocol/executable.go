package protocol

import (
	"errors"
	"path/filepath"
	"strings"
	"unicode"
)

// ValidateExecutable checks the executable token shared by planned actions and
// the host runner. It does not resolve the executable or interpret shell syntax.
// Whitespace and control characters are forbidden even in otherwise legitimate
// filenames: argv[0] is one executable, never a command line. A caller needing
// such a filename must explicitly invoke a shell and pass the path separately.
func ValidateExecutable(name string) error {
	if name == "" {
		return errors.New("command argv must include an executable")
	}
	if strings.IndexFunc(name, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return errors.New("executable must be a single token without whitespace or control characters; supply separate arguments or explicitly invoke a shell")
	}
	if !filepath.IsAbs(name) && strings.ContainsAny(name, `/\\`) {
		return errors.New("executable must be an absolute path or a simple name from the trusted PATH")
	}
	return nil
}
