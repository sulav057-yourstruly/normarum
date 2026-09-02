package control_test

import (
	"controlatlas/internal/control"
	"testing"
	"time"
)

func validSource() control.Source {
	return control.Source{
		Framework:  "NIST SP 800-53",
		Revision:   "5",
		Release:    "5.2.0",
		ImportedAt: time.Now().UTC(),
	}
}

func validCatalog() control.Catalog {
	return control.Catalog{
		Source: validSource(),
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
			{
				ID:       "AC-6(2)",
				Title:    "Non-Privileged Access for Nonsecurity Functions",
				Family:   "Access Control",
				ParentID: "AC-6",
				Kind:     control.KindEnhancement,
			},
			{
				ID:     "AC-7",
				Title:  "Unsuccessful Logon Attempts",
				Family: "Access Control",
				Kind:   control.KindControl,
			},
		},
	}
}

func TestCatalogValidate_Valid(t *testing.T) {
	cat := validCatalog()
	if err := cat.Validate(); err != nil {
		t.Fatalf("expected valid catalog, got error: %v", err)
	}
}

func TestCatalogValidate_MissingSource(t *testing.T) {
	tests := []struct {
		name string
		src  control.Source
	}{
		{"empty framework", control.Source{Revision: "5", Release: "5.2.0"}},
		{"empty revision", control.Source{Framework: "NIST", Release: "5.2.0"}},
		{"empty release", control.Source{Framework: "NIST", Revision: "5"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cat := validCatalog()
			cat.Source = tt.src
			if err := cat.Validate(); err == nil {
				t.Fatalf("expected validation error for %s", tt.name)
			}
		})
	}
}

func TestCatalogValidate_InvalidControlFields(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*control.Catalog)
		wantErr string
	}{
		{
			name: "empty ID",
			mutate: func(c *control.Catalog) {
				c.Controls[0].ID = ""
			},
			wantErr: "control ID cannot be empty",
		},
		{
			name: "empty title",
			mutate: func(c *control.Catalog) {
				c.Controls[0].Title = "   "
			},
			wantErr: "empty title",
		},
		{
			name: "invalid kind",
			mutate: func(c *control.Catalog) {
				c.Controls[0].Kind = "subcontrol"
			},
			wantErr: "invalid kind",
		},
		{
			name: "duplicate ID",
			mutate: func(c *control.Catalog) {
				c.Controls = append(c.Controls, control.Control{
					ID:     "AC-6",
					Title:  "Duplicate",
					Family: "Access Control",
					Kind:   control.KindControl,
				})
			},
			wantErr: "duplicate control ID",
		},
		{
			name: "missing parent ID",
			mutate: func(c *control.Catalog) {
				c.Controls[1].ParentID = ""
			},
			wantErr: "missing parent ID",
		},
		{
			name: "self-referencing parent",
			mutate: func(c *control.Catalog) {
				c.Controls[1].ParentID = c.Controls[1].ID
			},
			wantErr: "cannot be its own parent",
		},
		{
			name: "non-existent parent",
			mutate: func(c *control.Catalog) {
				c.Controls[1].ParentID = "AC-99"
			},
			wantErr: "references non-existent parent",
		},
		{
			name: "parent is enhancement not control",
			mutate: func(c *control.Catalog) {
				c.Controls[2].ParentID = "AC-6(1)"
			},
			wantErr: "must be a control",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cat := validCatalog()
			tt.mutate(&cat)
			err := cat.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
		})
	}
}

func TestCatalogGet(t *testing.T) {
	cat := validCatalog()

	tests := []struct {
		query    string
		wantID   string
		wantOK   bool
	}{
		{"AC-6", "AC-6", true},
		{"ac-6", "AC-6", true},
		{"Ac-6", "AC-6", true},
		{"AC-6(2)", "AC-6(2)", true},
		{"ac-6(2)", "AC-6(2)", true},
		{"ac-6.2", "AC-6(2)", true},
		{"AC-66", "", false},
		{"", "", false},
	}

	for _, tt := range tests {
		ctrl, ok := cat.Get(tt.query)
		if ok != tt.wantOK {
			t.Errorf("Get(%q) ok = %v, want %v", tt.query, ok, tt.wantOK)
		}
		if ok && ctrl.ID != tt.wantID {
			t.Errorf("Get(%q) ID = %q, want %q", tt.query, ctrl.ID, tt.wantID)
		}
	}
}

func TestCatalogSearch(t *testing.T) {
	cat := validCatalog()

	// Empty query returns nil
	if res := cat.Search("   "); res != nil {
		t.Fatalf("expected nil for empty query, got %v", res)
	}

	// Match by title
	res := cat.Search("privilege")
	if len(res) != 2 { // AC-6, AC-6(2)
		t.Fatalf("expected 2 matches for 'privilege', got %d", len(res))
	}

	// Match by ID
	res = cat.Search("ac-7")
	if len(res) != 1 || res[0].ID != "AC-7" {
		t.Fatalf("expected 1 match for 'ac-7', got %v", res)
	}
}

func TestCatalogVerify(t *testing.T) {
	cat := validCatalog()

	// Mode 1: Existence only
	v1 := cat.Verify("AC-6", "")
	if !v1.Exists || v1.TitleChecked || v1.OfficialTitle != "Least Privilege" {
		t.Fatalf("unexpected verification for existence only: %+v", v1)
	}

	// Mode 1: Non-existent
	v2 := cat.Verify("AC-66", "")
	if v2.Exists || v2.TitleChecked {
		t.Fatalf("unexpected verification for unknown control: %+v", v2)
	}

	// Mode 2: Title matches
	v3 := cat.Verify("ac-6", "Least Privilege")
	if !v3.Exists || !v3.TitleChecked || !v3.TitleMatches {
		t.Fatalf("expected title match: %+v", v3)
	}

	// Mode 2: Title matches case-insensitively
	v4 := cat.Verify("ac-6", "least privilege")
	if !v4.Exists || !v4.TitleChecked || !v4.TitleMatches {
		t.Fatalf("expected case-insensitive title match: %+v", v4)
	}

	// Mode 2: Title mismatch
	v5 := cat.Verify("ac-6", "Password Policy")
	if !v5.Exists || !v5.TitleChecked || v5.TitleMatches {
		t.Fatalf("expected title mismatch: %+v", v5)
	}
}

func TestCatalogSort(t *testing.T) {
	cat := control.Catalog{
		Source: validSource(),
		Controls: []control.Control{
			{ID: "IA-2", Title: "Identification and Authentication", Kind: control.KindControl},
			{ID: "AC-10", Title: "Concurrent Session Control", Kind: control.KindControl},
			{ID: "AC-6(2)", Title: "Non-Privileged Access", ParentID: "AC-6", Kind: control.KindEnhancement},
			{ID: "AC-6", Title: "Least Privilege", Kind: control.KindControl},
			{ID: "AC-6(1)", Title: "Authorize Access", ParentID: "AC-6", Kind: control.KindEnhancement},
			{ID: "AC-1", Title: "Policy and Procedures", Kind: control.KindControl},
		},
	}

	cat.Sort()

	expectedOrder := []string{"AC-1", "AC-6", "AC-6(1)", "AC-6(2)", "AC-10", "IA-2"}
	for i, want := range expectedOrder {
		if cat.Controls[i].ID != want {
			t.Errorf("at index %d: got %s, want %s", i, cat.Controls[i].ID, want)
		}
	}
}
