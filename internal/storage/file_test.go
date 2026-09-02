package storage_test

import (
	"normarum/internal/control"
	"normarum/internal/storage"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sampleCatalog() control.Catalog {
	return control.Catalog{
		Source: control.Source{
			Framework:  "NIST SP 800-53",
			Revision:   "5",
			Release:    "5.2.0",
			ImportedAt: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC),
		},
		Controls: []control.Control{
			{
				ID:     "AC-6",
				Title:  "Least Privilege",
				Family: "Access Control",
				Kind:   control.KindControl,
			},
			{
				ID:       "AC-6(1)",
				Title:    "Authorize Access to Security Functions",
				Family:   "Access Control",
				ParentID: "AC-6",
				Kind:     control.KindEnhancement,
			},
		},
	}
}

func TestSaveAndLoad_RoundTrip(t *testing.T) {
	tempDir := t.TempDir()
	catPath := filepath.Join(tempDir, "catalog.json")

	original := sampleCatalog()
	if err := storage.Save(catPath, original); err != nil {
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

	if loaded.Source.Framework != original.Source.Framework ||
		loaded.Source.Revision != original.Source.Revision ||
		loaded.Source.Release != original.Source.Release {
		t.Errorf("Source mismatch: got %+v, want %+v", loaded.Source, original.Source)
	}

	if len(loaded.Controls) != len(original.Controls) {
		t.Fatalf("Controls count mismatch: got %d, want %d", len(loaded.Controls), len(original.Controls))
	}

	for i := range original.Controls {
		if loaded.Controls[i] != original.Controls[i] {
			t.Errorf("Control[%d] mismatch: got %+v, want %+v", i, loaded.Controls[i], original.Controls[i])
		}
	}
}

func TestSave_DoesNotMutateCallerCatalog(t *testing.T) {
	tempDir := t.TempDir()
	catPath := filepath.Join(tempDir, "catalog.json")

	original := sampleCatalog()
	// Deliberately unsorted order to verify Save does not sort in place
	original.Controls[0], original.Controls[1] = original.Controls[1], original.Controls[0]
	firstIDBefore := original.Controls[0].ID

	if err := storage.Save(catPath, original); err != nil {
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

	if err := os.WriteFile(catPath, []byte("not-valid-json"), 0644); err != nil {
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

	if err := os.WriteFile(catPath, []byte(invalidJSON), 0644); err != nil {
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
