package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"normarum/internal/control"
	"os"
	"path/filepath"
)

// Save writes a normalized control.Catalog to disk as formatted JSON without mutating the catalog.
func Save(path string, cat *control.Catalog) error {
	if cat == nil {
		return errors.New("cannot save nil catalog")
	}
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create directory %q: %w", dir, err)
		}
	}

	data, err := json.MarshalIndent(cat, "", "  ")
	if err != nil {
		return fmt.Errorf("encode catalog JSON: %w", err)
	}

	// Add trailing newline for POSIX-friendly file formatting
	data = append(data, '\n')

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write catalog file %q: %w", path, err)
	}

	return nil
}

// Load reads and unmarshals a normalized control.Catalog from a JSON file.
// It performs no domain validation; the caller is responsible for validating the loaded catalog.
func Load(path string) (control.Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return control.Catalog{}, fmt.Errorf("read catalog file %q: %w", path, err)
	}

	var cat control.Catalog
	if err := json.Unmarshal(data, &cat); err != nil {
		return control.Catalog{}, fmt.Errorf("decode catalog JSON %q: %w", path, err)
	}

	return cat, nil
}
