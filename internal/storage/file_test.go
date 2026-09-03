package storage_test

import (
	"normarum/internal/core"
	"normarum/internal/storage"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func sampleCatalog() core.Catalog {
	return core.Catalog{
		Source: core.Source{
			Authority:    "NIST",
			Standard:     "SP 800-53",
			Revision:     "5",
			Release:      "5.2.0",
			ImportedFrom: "data/raw/test.json",
			SHA256:       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			ImportedAt:   time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC),
		},
		Controls: []core.Control{
			{
				ID:     "AC-6",
				Title:  "Least Privilege",
				Family: "Access Control",
				Kind:   core.KindControl,
				Status: core.StatusActive,
			},
			{
				ID:       "AC-6(1)",
				Title:    "Authorize Access to Security Functions",
				Family:   "Access Control",
				ParentID: "AC-6",
				Kind:     core.KindEnhancement,
				Status:   core.StatusActive,
			},
		},
	}
}

func TestSaveAndLoad_RoundTrip(t *testing.T) {
	tempDir := t.TempDir()
	catPath := filepath.Join(tempDir, "catalog.json")

	original := sampleCatalog()
	if err := storage.Save(catPath, &original); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := storage.Load(catPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Must validate cleanly
	if err := loaded.Validate(); err != nil {
		t.Fatalf("Loaded catalog validation failed: %v", err)
	}

	if loaded.Source.Authority != original.Source.Authority ||
		loaded.Source.Standard != original.Source.Standard ||
		loaded.Source.Revision != original.Source.Revision ||
		loaded.Source.Release != original.Source.Release ||
		loaded.Source.SHA256 != original.Source.SHA256 {
		t.Errorf("Source mismatch: got %+v, want %+v", loaded.Source, original.Source)
	}

	if len(loaded.Controls) != len(original.Controls) {
		t.Fatalf("Controls count mismatch: got %d, want %d", len(loaded.Controls), len(original.Controls))
	}

	for i := range original.Controls {
		if !reflect.DeepEqual(loaded.Controls[i], original.Controls[i]) {
			t.Errorf("Control[%d] mismatch: got %+v, want %+v", i, loaded.Controls[i], original.Controls[i])
		}
	}
}

func TestSave_NilCatalog(t *testing.T) {
	tempDir := t.TempDir()
	catPath := filepath.Join(tempDir, "catalog.json")

	if err := storage.Save(catPath, nil); err == nil {
		t.Fatal("expected error saving nil catalog, got nil")
	}
}

func TestSave_DoesNotMutateCallerCatalog(t *testing.T) {
	tempDir := t.TempDir()
	catPath := filepath.Join(tempDir, "catalog.json")

	original := sampleCatalog()
	// Deliberately unsorted order to verify Save does not sort in place
	original.Controls[0], original.Controls[1] = original.Controls[1], original.Controls[0]
	firstIDBefore := original.Controls[0].ID

	if err := storage.Save(catPath, &original); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	if original.Controls[0].ID != firstIDBefore {
		t.Fatalf("Save mutated caller's slice: got %s, want %s", original.Controls[0].ID, firstIDBefore)
	}
}

func TestLoad_NonExistentFile(t *testing.T) {
	_, err := storage.Load("non_existent_file.json")
	if err == nil {
		t.Fatal("expected error loading non-existent file, got nil")
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	tempDir := t.TempDir()
	catPath := filepath.Join(tempDir, "corrupted.json")

	if err := os.WriteFile(catPath, []byte("not-valid-json"), 0o644); err != nil {
		t.Fatalf("failed to write corrupted file: %v", err)
	}

	_, err := storage.Load(catPath)
	if err == nil {
		t.Fatal("expected decode error, got nil")
	}
}

func TestLoad_CorruptCatalogDomainValidation(t *testing.T) {
	tempDir := t.TempDir()
	catPath := filepath.Join(tempDir, "semantic_invalid.json")

	// Missing release & duplicate controls
	invalidJSON := `{
		"source": { "framework": "NIST SP 800-53", "revision": "5", "release": "" },
		"controls": [
			{ "id": "AC-6", "title": "First", "kind": "control" },
			{ "id": "AC-6", "title": "Duplicate", "kind": "control" }
		]
	}`

	if err := os.WriteFile(catPath, []byte(invalidJSON), 0o644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	// Storage load succeeds because syntax is valid JSON
	cat, err := storage.Load(catPath)
	if err != nil {
		t.Fatalf("storage.Load unexpectedly failed on valid JSON syntax: %v", err)
	}

	// Domain validation must catch the semantic invalidity
	if err := cat.Validate(); err == nil {
		t.Fatal("expected domain validation to reject loaded invalid catalog, got nil")
	}
}
