package piiscanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSpacyDetectorDetectWorkingDir(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T) ([]string, string)
		wantError string
	}{
		{
			name: "finds script in first directory",
			setup: func(t *testing.T) ([]string, string) {
				dir := createSpacyTestDir(t)
				return []string{dir}, dir
			},
		},
		{
			name: "skips missing directory",
			setup: func(t *testing.T) ([]string, string) {
				missing := filepath.Join(t.TempDir(), "missing")
				dir := createSpacyTestDir(t)
				return []string{missing, dir}, dir
			},
		},
		{
			name: "returns error when script is absent",
			setup: func(t *testing.T) ([]string, string) {
				return []string{t.TempDir()}, ""
			},
			wantError: "spacy file not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workDirs, want := tt.setup(t)
			detector := NewSpacyDetector().WithWorkDirs(workDirs)

			got, err := detector.detectWorkingDir()
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("detect working directory: got error %v, want error containing %q", err, tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("detect working directory: %v", err)
			}
			if got != want {
				t.Fatalf("detect working directory: got %q, want %q", got, want)
			}
		})
	}
}

func createSpacyTestDir(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, spacyFileName), []byte(""), 0o600); err != nil {
		t.Fatalf("create SpaCy test script: %v", err)
	}
	return dir
}
