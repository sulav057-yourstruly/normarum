package main

import (
	"normarum/internal/control"
	"normarum/internal/storage"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func createTestCatalog(t *testing.T, path string) {
	t.Helper()
	cat := control.Catalog{
		Source: control.Source{
			Framework:  "NIST SP 800-53",
			Revision:   "5",
			Release:    "5.2.0",
			ImportedAt: time.Now().UTC(),
		},
		Controls: []control.Control{
			{
				ID:     "AC-6",
				Title:  "Least Privilege",
				Family: "Access Control",
				Kind:   control.KindControl,
			},
			{
				ID:       "AC-6(2)",
				Title:    "Non-Privileged Access for Nonsecurity Functions",
				Family:   "Access Control",
				ParentID: "AC-6",
				Kind:     control.KindEnhancement,
			},
		},
	}
	if err := storage.Save(path, cat); err != nil {
		t.Fatalf("failed to create test catalog: %v", err)
	}
}

func TestCLIGet_WithSourceDirect(t *testing.T) {
	// Tests Milestone 1 vertical slice: get --source <fixture> AC-6
	fixturePath := filepath.Join("..", "..", "testdata", "nist-small.json")
	code := runGet([]string{"--source", fixturePath, "AC-6"})
	if code != ExitSuccess {
		t.Errorf("runGet returned %d, want %d", code, ExitSuccess)
	}

	// Enhancement lookup
	code = runGet([]string{"--source", fixturePath, "AC-6(2)"})
	if code != ExitSuccess {
		t.Errorf("runGet for enhancement returned %d, want %d", code, ExitSuccess)
	}

	// Missing control
	code = runGet([]string{"--source", fixturePath, "AC-99"})
	if code != ExitVerifyFail {
		t.Errorf("runGet for missing control returned %d, want %d", code, ExitVerifyFail)
	}
}

func TestCLIGet_MissingArgs(t *testing.T) {
	code := runGet([]string{})
	if code != ExitProgramError {
		t.Errorf("expected ExitProgramError for missing args, got %d", code)
	}
}

func TestCLISearch_EmptyQuery(t *testing.T) {
	code := runSearch([]string{""})
	if code != ExitProgramError {
		t.Errorf("expected ExitProgramError for empty query, got %d", code)
	}

	code = runSearch([]string{"   "})
	if code != ExitProgramError {
		t.Errorf("expected ExitProgramError for whitespace query, got %d", code)
	}
}

func TestCLIVerify_MissingArgs(t *testing.T) {
	code := runVerify([]string{})
	if code != ExitProgramError {
		t.Errorf("expected ExitProgramError for missing args, got %d", code)
	}
}

func TestCLIImport_MissingFile(t *testing.T) {
	code := runImport([]string{"non_existent_oscal.json"})
	if code != ExitProgramError {
		t.Errorf("expected ExitProgramError for missing file, got %d", code)
	}
}

func TestCLI_DefaultCatalogOperations(t *testing.T) {
	// Setup temporary working environment for data/catalog.json
	tempDir := t.TempDir()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current wd: %v", err)
	}
	defer func() {
		_ = os.Chdir(origWd)
	}()

	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir to tempDir: %v", err)
	}

	createTestCatalog(t, "data/catalog.json")

	// Test Get
	if code := runGet([]string{"AC-6"}); code != ExitSuccess {
		t.Errorf("runGet(AC-6) = %d, want %d", code, ExitSuccess)
	}
	if code := runGet([]string{"AC-6(2)"}); code != ExitSuccess {
		t.Errorf("runGet(AC-6(2)) = %d, want %d", code, ExitSuccess)
	}
	if code := runGet([]string{"AC-99"}); code != ExitVerifyFail {
		t.Errorf("runGet(AC-99) = %d, want %d", code, ExitVerifyFail)
	}

	// Test Search
	if code := runSearch([]string{"privilege"}); code != ExitSuccess {
		t.Errorf("runSearch('privilege') = %d, want %d", code, ExitSuccess)
	}
	if code := runSearch([]string{"nonexistent"}); code != ExitSuccess {
		t.Errorf("runSearch('nonexistent') = %d, want %d", code, ExitSuccess)
	}

	// Test Verify Mode 1: existence only
	if code := runVerify([]string{"AC-6"}); code != ExitSuccess {
		t.Errorf("runVerify(AC-6) = %d, want %d", code, ExitSuccess)
	}
	if code := runVerify([]string{"AC-99"}); code != ExitVerifyFail {
		t.Errorf("runVerify(AC-99) = %d, want %d", code, ExitVerifyFail)
	}

	// Test Verify Mode 2: title matches
	if code := runVerify([]string{"AC-6", "Least Privilege"}); code != ExitSuccess {
		t.Errorf("runVerify(AC-6, Least Privilege) = %d, want %d", code, ExitSuccess)
	}
	if code := runVerify([]string{"AC-6", "Password Policy"}); code != ExitVerifyFail {
		t.Errorf("runVerify(AC-6, Password Policy) = %d, want %d", code, ExitVerifyFail)
	}
}
