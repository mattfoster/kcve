package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStripHeaders(t *testing.T) {
	// Get all test files from testdata directory
	testFiles, err := filepath.Glob("pkg/utils/testdata/*.input.txt")
	if err != nil {
		t.Fatalf("Failed to read test files: %v", err)
	}

	for _, inputFile := range testFiles {
		// Get corresponding expected output file
		expectedFile := strings.Replace(inputFile, ".input.txt", ".expected.txt", 1)

		testName := filepath.Base(inputFile)
		testName = strings.TrimSuffix(testName, ".input.txt")

		t.Run(testName, func(t *testing.T) {
			// Read input file
			input, err := os.ReadFile(inputFile)
			if err != nil {
				t.Fatalf("Failed to read input file %s: %v", inputFile, err)
			}

			// Read expected output file
			expected, err := os.ReadFile(expectedFile)
			if err != nil {
				t.Fatalf("Failed to read expected file %s: %v", expectedFile, err)
			}

			got := StripHeaders(string(input))
			if got != string(expected) {
				t.Errorf("StripHeaders() = %v, want %v", got, string(expected))
			}
		})
	}
}
