package control_test

import (
	"normarum/internal/control"
	"testing"
	"time"
)

func strPtr(s string) *string {
	return &s
}

func validSource() control.Source {
	return control.Source{
		Authority:    "NIST",
		Standard:     "SP 800-53",
		Revision:     "5",
		Release:      "5.2.0",
		ImportedFrom: "data/raw/test.json",
		SHA256:       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		ImportedAt:   time.Now().UTC(),
	}
}

func validCatalog() control.Catalog {
	return control.Catalog{
		Source: validSource(),
		Controls: []control.Control{
			{
				ID:     "AC-2",
				Title:  "Account Management",
				Family: "Access Control",
				Kind:   control.KindControl,
				Status: control.StatusActive,
			},
			{
				ID:     "AC-6",
				Title:  "Least Privilege",
				Family: "Access Control",
				Kind:   control.KindControl,
				Status: control.StatusActive,
			},
			{
				ID:       "AC-6(1)",
				Title:    "Authorize Access to Security Functions",
				Family:   "Access Control",
				ParentID: "AC-6",
				Kind:     control.KindEnhancement,
				Status:   control.StatusActive,
			},
			{
				ID:       "AC-6(2)",
				Title:    "Non-Privileged Access for Nonsecurity Functions",
				Family:   "Access Control",
				ParentID: "AC-6",
				Kind:     control.KindEnhancement,
				Status:   control.StatusActive,
			},
			{
				ID:     "AC-7",
				Title:  "Unsuccessful Logon Attempts",
				Family: "Access Control",
				Kind:   control.KindControl,
				Status: control.StatusActive,
			},
			{
				ID:     "AC-13",
				Title:  "Supervision and Review — Access Control",
				Family: "Access Control",
				Kind:   control.KindControl,
				Status: control.StatusWithdrawn,
				References: []control.Reference{
					{ID: "AC-2", Relation: "incorporated-into"},
					{ID: "AU-6", Relation: "incorporated-into"},
				},
			},
			{
				ID:     "AU-6",
				Title:  "Audit Record Review, Analysis, and Reporting",
				Family: "Audit and Accountability",
				Kind:   control.KindControl,
				Status: control.StatusActive,
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
	validSHA := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	tests := []struct {
		name string
		src  control.Source
	}{
		{"empty authority", control.Source{Standard: "SP 800-53", Revision: "5", Release: "5.2.0", SHA256: validSHA}},
		{"empty standard", control.Source{Authority: "NIST", Revision: "5", Release: "5.2.0", SHA256: validSHA}},
		{"empty revision", control.Source{Authority: "NIST", Standard: "SP 800-53", Release: "5.2.0", SHA256: validSHA}},
		{"empty release", control.Source{Authority: "NIST", Standard: "SP 800-53", Revision: "5", SHA256: validSHA}},
		{"empty sha256", control.Source{Authority: "NIST", Standard: "SP 800-53", Revision: "5", Release: "5.2.0"}},
		{"invalid hex sha256", control.Source{Authority: "NIST", Standard: "SP 800-53", Revision: "5", Release: "5.2.0", SHA256: "not-a-hex-hash"}},
		{"short sha256", control.Source{Authority: "NIST", Standard: "SP 800-53", Revision: "5", Release: "5.2.0", SHA256: "abcd"}},
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
			name: "invalid status",
			mutate: func(c *control.Catalog) {
				c.Controls[0].Status = "deprecated"
			},
			wantErr: "invalid status",
		},
		{
			name: "empty status",
			mutate: func(c *control.Catalog) {
				c.Controls[0].Status = ""
			},
			wantErr: "invalid status",
		},
		{
			name: "duplicate ID",
			mutate: func(c *control.Catalog) {
				c.Controls[1].ID = c.Controls[0].ID
			},
			wantErr: "duplicate control ID",
		},
		{
			name: "missing parent ID",
			mutate: func(c *control.Catalog) {
				c.Controls[2].ParentID = ""
			},
			wantErr: "missing parent ID",
		},
		{
			name: "self-referencing parent",
			mutate: func(c *control.Catalog) {
				c.Controls[2].ParentID = c.Controls[2].ID
			},
			wantErr: "cannot be its own parent",
		},
		{
			name: "non-existent parent",
			mutate: func(c *control.Catalog) {
				c.Controls[2].ParentID = "NON-EXISTENT"
			},
			wantErr: "non-existent parent",
		},
		{
			name: "parent is enhancement not control",
			mutate: func(c *control.Catalog) {
				c.Controls[3].ParentID = c.Controls[2].ID // points to AC-6(1)
			},
			wantErr: "must be a control",
		},
		{
			name: "reference with empty target ID",
			mutate: func(c *control.Catalog) {
				c.Controls[5].References = []control.Reference{
					{ID: "", Relation: "incorporated-into"},
				}
			},
			wantErr: "reference with empty target ID",
		},
		{
			name: "reference with empty relation",
			mutate: func(c *control.Catalog) {
				c.Controls[5].References = []control.Reference{
					{ID: "AC-2", Relation: "   "},
				}
			},
			wantErr: "empty relation",
		},
		{
			name: "self-referencing reference",
			mutate: func(c *control.Catalog) {
				c.Controls[5].References = []control.Reference{
					{ID: c.Controls[5].ID, Relation: "incorporated-into"},
				}
			},
			wantErr: "cannot reference itself",
		},
		{
			name: "reference to non-existent target",
			mutate: func(c *control.Catalog) {
				c.Controls[5].References = []control.Reference{
					{ID: "ZZ-99", Relation: "incorporated-into"},
				}
			},
			wantErr: "references non-existent target",
		},
		{
			name: "duplicate reference within control",
			mutate: func(c *control.Catalog) {
				c.Controls[5].References = []control.Reference{
					{ID: "AC-2", Relation: "incorporated-into"},
					{ID: "AC-2", Relation: "incorporated-into"},
				}
			},
			wantErr: "duplicate reference",
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

	// Direct lookup
	ctrl, ok := cat.Get("AC-6")
	if !ok || ctrl.Title != "Least Privilege" {
		t.Fatalf("failed to find AC-6: %+v", ctrl)
	}

	// Forgiving discovery lookup: lowercase with hyphen
	ctrl, ok = cat.Get("ac-6")
	if !ok || ctrl.ID != "AC-6" {
		t.Fatalf("failed forgiving lookup for ac-6: %+v", ctrl)
	}

	// Forgiving discovery lookup: lowercase with space
	ctrl, ok = cat.Get("ac 6")
	if !ok || ctrl.ID != "AC-6" {
		t.Fatalf("failed forgiving lookup for 'ac 6': %+v", ctrl)
	}

	// Forgiving discovery lookup: enhancement with dot
	ctrl, ok = cat.Get("ac-6.2")
	if !ok || ctrl.ID != "AC-6(2)" {
		t.Fatalf("failed forgiving lookup for ac-6.2: %+v", ctrl)
	}

	// Non-existent control
	_, ok = cat.Get("AC-99")
	if ok {
		t.Fatal("expected false for non-existent control")
	}
}

func TestCatalogSearch(t *testing.T) {
	cat := validCatalog()

	// Empty query returns nil
	if res := cat.Search(""); res != nil {
		t.Fatalf("expected nil for empty search, got %v", res)
	}

	// Match active controls
	res := cat.Search("privilege")
	if len(res) != 2 { // AC-6 and AC-6(2)
		t.Fatalf("expected 2 matches for 'privilege', got %d", len(res))
	}

	// Match withdrawn controls
	res = cat.Search("Supervision")
	if len(res) != 1 || res[0].ID != "AC-13" || res[0].Status != control.StatusWithdrawn {
		t.Fatalf("expected 1 withdrawn match for 'Supervision', got %v", res)
	}

	// Match by ID
	res = cat.Search("ac-7")
	if len(res) != 1 || res[0].ID != "AC-7" {
		t.Fatalf("expected 1 match for 'ac-7', got %v", res)
	}
}

func TestCatalogVerify(t *testing.T) {
	cat := validCatalog()

	// Mode 1: Active control existence only with title omitted (PASS)
	v1 := cat.Verify("AC-6", nil)
	if !v1.Exists || v1.NonCanonical || v1.TitleChecked || v1.Status != control.StatusActive || v1.OfficialTitle != "Least Privilege" {
		t.Fatalf("unexpected verification for active existence only: %+v", v1)
	}

	// Explicit empty title supplied: should evaluate title and FAIL
	vEmpty := cat.Verify("AC-6", strPtr(""))
	if !vEmpty.Exists || !vEmpty.TitleChecked || vEmpty.TitleMatches {
		t.Fatalf("expected explicit empty title to fail title match: %+v", vEmpty)
	}

	// Decision Tree Precedence Test 1: Non-canonical reference halts before checking status!
	// ac-13 is withdrawn, but because the citation was "ac-13" instead of "AC-13",
	// it must halt at non-canonical and NOT report withdrawn yet.
	vNCWithdrawn := cat.Verify("ac-13", nil)
	if !vNCWithdrawn.Exists || !vNCWithdrawn.NonCanonical || vNCWithdrawn.CanonicalID != "AC-13" || vNCWithdrawn.TitleChecked {
		t.Fatalf("expected non-canonical to halt before status evaluation: %+v", vNCWithdrawn)
	}

	// Non-canonical reference halts before checking title!
	vNCTitle := cat.Verify("ac-6", strPtr("Least Privilege"))
	if !vNCTitle.Exists || !vNCTitle.NonCanonical || vNCTitle.CanonicalID != "AC-6" || vNCTitle.TitleChecked {
		t.Fatalf("expected non-canonical to halt before title evaluation: %+v", vNCTitle)
	}

	// Strict whitespace rejection: " AC-6" must not silently trim!
	vWhitespace := cat.Verify(" AC-6", nil)
	if !vWhitespace.NonCanonical || vWhitespace.CanonicalID != "AC-6" {
		t.Fatalf("expected untrimmed ID to be caught as non-canonical: %+v", vWhitespace)
	}

	// Unknown control
	vUnknown := cat.Verify("AC-66", nil)
	if vUnknown.Exists || vUnknown.NonCanonical || vUnknown.TitleChecked {
		t.Fatalf("unexpected verification for unknown control: %+v", vUnknown)
	}

	// Canonical Withdrawn control: reaches withdrawn branch
	vWithdrawn1 := cat.Verify("AC-13", nil)
	if !vWithdrawn1.Exists || vWithdrawn1.NonCanonical || vWithdrawn1.Status != control.StatusWithdrawn || len(vWithdrawn1.References) != 2 {
		t.Fatalf("expected withdrawn control verification metadata: %+v", vWithdrawn1)
	}

	// Canonical Withdrawn control with title: halts before title evaluation
	vWithdrawnWithTitle := cat.Verify("AC-13", strPtr("Supervision and Review — Access Control"))
	if !vWithdrawnWithTitle.Exists || vWithdrawnWithTitle.Status != control.StatusWithdrawn || vWithdrawnWithTitle.TitleChecked {
		t.Fatalf("expected withdrawn control to halt before title evaluation: %+v", vWithdrawnWithTitle)
	}

	// Mode 2: Exact title match (PASS)
	vExact := cat.Verify("AC-6", strPtr("Least Privilege"))
	if !vExact.Exists || vExact.NonCanonical || !vExact.TitleChecked || !vExact.TitleMatches || vExact.Status != control.StatusActive {
		t.Fatalf("expected exact title match: %+v", vExact)
	}

	// Mode 2: Strict case sensitivity (FAIL) - no silent case-folding
	vCaseMismatch := cat.Verify("AC-6", strPtr("least privilege"))
	if !vCaseMismatch.Exists || !vCaseMismatch.TitleChecked || vCaseMismatch.TitleMatches {
		t.Fatalf("expected case mismatch to fail title match: %+v", vCaseMismatch)
	}

	// Mode 2: Strict whitespace in title (FAIL) - no silent trimming
	vTitleWhitespace := cat.Verify("AC-6", strPtr("Least Privilege "))
	if !vTitleWhitespace.Exists || !vTitleWhitespace.TitleChecked || vTitleWhitespace.TitleMatches {
		t.Fatalf("expected title with trailing whitespace to fail: %+v", vTitleWhitespace)
	}

	// Mode 2: Title mismatch
	vMismatch := cat.Verify("AC-6", strPtr("Password Policy"))
	if !vMismatch.Exists || !vMismatch.TitleChecked || vMismatch.TitleMatches {
		t.Fatalf("expected title mismatch to fail: %+v", vMismatch)
	}
}

func TestCatalogSort(t *testing.T) {
	cat := control.Catalog{
		Source: validSource(),
		Controls: []control.Control{
			{ID: "IA-2", Title: "Identification and Authentication", Kind: control.KindControl, Status: control.StatusActive},
			{ID: "AC-10", Title: "Concurrent Session Control", Kind: control.KindControl, Status: control.StatusActive},
			{ID: "AC-6(2)", Title: "Non-Privileged Access", ParentID: "AC-6", Kind: control.KindEnhancement, Status: control.StatusActive},
			{ID: "AC-6", Title: "Least Privilege", Kind: control.KindControl, Status: control.StatusActive},
			{ID: "AC-6(1)", Title: "Authorize Access", ParentID: "AC-6", Kind: control.KindEnhancement, Status: control.StatusActive},
			{ID: "AC-1", Title: "Policy and Procedures", Kind: control.KindControl, Status: control.StatusActive},
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

func TestCatalogValidate_EmptyControls(t *testing.T) {
	cat := validCatalog()
	cat.Controls = nil
	if err := cat.Validate(); err == nil {
		t.Fatal("expected error for empty controls, got nil")
	}

	cat.Controls = []control.Control{}
	if err := cat.Validate(); err == nil {
		t.Fatal("expected error for empty controls slice, got nil")
	}
}
