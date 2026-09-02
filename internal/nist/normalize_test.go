package nist_test

import (
	"controlatlas/internal/control"
	"controlatlas/internal/nist"
	"os"
	"testing"
)

func TestNormalize_ValidFixture(t *testing.T) {
	f, err := os.Open("../../testdata/nist-small.json")
	if err != nil {
		t.Fatalf("failed to open test fixture: %v", err)
	}
	defer f.Close()

	doc, err := nist.Parse(f)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	cat, err := nist.Normalize(doc)
	if err != nil {
		t.Fatalf("Normalize failed: %v", err)
	}

	if cat.Source.Framework != "NIST SP 800-53" {
		t.Errorf("Framework = %q, want 'NIST SP 800-53'", cat.Source.Framework)
	}
	if cat.Source.Revision != "5" {
		t.Errorf("Revision = %q, want '5'", cat.Source.Revision)
	}
	if cat.Source.Release != "5.2.0" {
		t.Errorf("Release = %q, want '5.2.0'", cat.Source.Release)
	}

	// Must validate cleanly
	if err := cat.Validate(); err != nil {
		t.Fatalf("normalized catalog failed domain validation: %v", err)
	}

	// Controls should be AC-6, AC-6(1), AC-6(2), AC-7
	if len(cat.Controls) != 4 {
		t.Fatalf("expected 4 controls, got %d", len(cat.Controls))
	}

	ac6, ok := cat.Get("AC-6")
	if !ok || ac6.Title != "Least Privilege" || ac6.Kind != control.KindControl {
		t.Fatalf("AC-6 mismatch: %+v", ac6)
	}

	ac6_2, ok := cat.Get("AC-6(2)")
	if !ok || ac6_2.ParentID != "AC-6" || ac6_2.Kind != control.KindEnhancement {
		t.Fatalf("AC-6(2) mismatch: %+v", ac6_2)
	}

	ac7, ok := cat.Get("AC-7")
	if !ok || ac7.Title != "Unsuccessful Logon Attempts" || ac7.Kind != control.KindControl {
		t.Fatalf("AC-7 mismatch: %+v", ac7)
	}
}

func TestNormalize_SourceControlID(t *testing.T) {
	tests := []struct {
		input   string
		wantID  string
		wantErr bool
	}{
		{"ac-6", "AC-6", false},
		{"ac-1", "AC-1", false},
		{"sc-7", "SC-7", false},
		{"pm-1", "PM-1", false},
		{"ac-6.2", "AC-6(2)", false},
		{"ac-6.10", "AC-6(10)", false},
		// Strict rejection cases
		{"ac-06.02", "", true}, // leading zero
		{"ac-06", "", true},    // leading zero
		{"ac6.2", "", true},    // missing hyphen
		{"AC_06", "", true},    // wrong case & underscore
		{"", "", true},         // empty
	}

	for _, tt := range tests {
		doc := nist.Document{
			Catalog: nist.Catalog{
				Metadata: nist.Metadata{Version: "5.2.0"},
				Groups: []nist.Group{
					{
						Title: "Access Control",
						Controls: []nist.Control{
							{ID: tt.input, Title: "Test Control"},
						},
					},
				},
			},
		}

		cat, err := nist.Normalize(doc)
		if tt.wantErr {
			if err == nil {
				t.Errorf("Normalize(%q) expected error, got success with ID %q", tt.input, cat.Controls[0].ID)
			}
		} else {
			if err != nil {
				t.Errorf("Normalize(%q) unexpected error: %v", tt.input, err)
			} else if len(cat.Controls) != 1 || cat.Controls[0].ID != tt.wantID {
				t.Errorf("Normalize(%q) = %q, want %q", tt.input, cat.Controls[0].ID, tt.wantID)
			}
		}
	}
}

func TestNormalize_EmptyRelease(t *testing.T) {
	doc := nist.Document{
		Catalog: nist.Catalog{
			Metadata: nist.Metadata{Version: "   "},
		},
	}
	_, err := nist.Normalize(doc)
	if err == nil {
		t.Fatal("expected error for empty metadata version, got nil")
	}
}
