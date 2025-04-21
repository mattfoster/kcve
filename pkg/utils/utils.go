package utils

import (
	"strings"
)

// StripHeaders removes email headers from the content by finding the first blank line
func StripHeaders(content string) string {
	// Strip email headers by finding the first blank line
	lines := strings.Split(content, "\n")
	headerEnd := 0
	for i, line := range lines {
		if line == "" {
			headerEnd = i + 1
			break
		}
	}
	if headerEnd > 0 {
		content = strings.Join(lines[headerEnd:], "\n")
	}

	return content
}
