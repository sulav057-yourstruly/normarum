package nist_test

import (
	"normarum/internal/nist"
	"os"
	"strings"
	"testing"
)

func TestParse_ValidFixture(t *testing.T) {
	f, err := os.Open("../../testdata/nist-small.json")
	if err != nil {
		t.Fatalf("failed to open test fixture: %v", err)
	}
	defer f.Close()

	doc, err := nist.Parse(f)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if doc.Catalog.Metadata.Version != "5.2.0" {
		t.Errorf("Metadata.Version = %q, want %q", doc.Catalog.Metadata.Version, "5.2.0")
	}

	if len(doc.Catalog.Groups) != 1 {
		t.Fatalf("Groups len = %d, want 1", len(doc.Catalog.Groups))
	}

	group := doc.Catalog.Groups[0]
	if group.Title != "Access Control" {
		t.Errorf("Group.Title = %q, want 'Access Control'", group.Title)
	}

	if len(group.Controls) != 2 { // ac-6, ac-7
		t.Fatalf("Group.Controls len = %d, want 2", len(group.Controls))
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	_, err := nist.Parse(strings.NewReader("{not-valid-json"))
	if err == nil {
		t.Fatal("expected error on invalid JSON, got nil")
	}
}

func TestParse_NilReader(t *testing.T) {
	_, err := nist.Parse(nil)
	if err == nil {
		t.Fatal("expected error on nil reader, got nil")
	}
}
