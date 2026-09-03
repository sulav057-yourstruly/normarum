package nist80053_test

import (
	"normarum/internal/frameworks/nist80053"
	"os"
	"strings"
	"testing"
)

func TestParse_ValidFixture(t *testing.T) {
	f, err := os.Open("../../../testdata/nist-small.json")
	if err != nil {
		t.Fatalf("failed to open test fixture: %v", err)
	}
	defer f.Close()

	doc, err := nist80053.Parse(f)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if doc.Catalog.Metadata.Version != "5.2.0" {
		t.Errorf("Metadata.Version = %q, want %q", doc.Catalog.Metadata.Version, "5.2.0")
	}

	if len(doc.Catalog.Groups) != 3 {
		t.Fatalf("Groups len = %d, want 3", len(doc.Catalog.Groups))
	}

	group := doc.Catalog.Groups[0]
	if group.Title != "Access Control" {
		t.Errorf("Group.Title = %q, want 'Access Control'", group.Title)
	}

	if len(group.Controls) != 4 { // ac-2, ac-6, ac-7, ac-13
		t.Fatalf("Group.Controls len = %d, want 4", len(group.Controls))
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	_, err := nist80053.Parse(strings.NewReader("{not-valid-json"))
	if err == nil {
		t.Fatal("expected error on invalid JSON, got nil")
	}
}

func TestParse_NilReader(t *testing.T) {
	_, err := nist80053.Parse(nil)
	if err == nil {
		t.Fatal("expected error on nil reader, got nil")
	}
}

func TestParse_TrailingData(t *testing.T) {
	validWithTrailing := `{"catalog":{"metadata":{"version":"5.2.0"}}} {"unexpected": "trailing"}`
	_, err := nist80053.Parse(strings.NewReader(validWithTrailing))
	if err == nil {
		t.Fatal("expected error on trailing data after document, got nil")
	}
}
