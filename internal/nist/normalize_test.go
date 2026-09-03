package nist_test

import (
	"normarum/internal/control"
	"normarum/internal/nist"
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

	if cat.Source.Authority != "NIST" {
		t.Errorf("Authority = %q, want 'NIST'", cat.Source.Authority)
	}
	if cat.Source.Standard != "SP 800-53" {
		t.Errorf("Standard = %q, want 'SP 800-53'", cat.Source.Standard)
	}
	if cat.Source.Revision != "5" {
		t.Errorf("Revision = %q, want '5'", cat.Source.Revision)
	}
	if cat.Source.Release != "5.2.0" {
		t.Errorf("Release = %q, want '5.2.0'", cat.Source.Release)
	}

	// In the trusted loading boundary, SHA256 is attached before Validate()
	cat.Source.SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if err := cat.Validate(); err != nil {
		t.Fatalf("normalized catalog failed domain validation: %v", err)
	}

	// Controls: AC-2, AC-6, AC-6(1), AC-6(2), AC-7, AC-13, AU-6, SC-19 (8 total)
	if len(cat.Controls) != 8 {
		t.Fatalf("expected 8 controls, got %d", len(cat.Controls))
	}

	ac6, ok := cat.Get("AC-6")
	if !ok || ac6.Title != "Least Privilege" || ac6.Kind != control.KindControl || ac6.Status != control.StatusActive {
		t.Fatalf("AC-6 mismatch: %+v", ac6)
	}

	ac6_2, ok := cat.Get("AC-6(2)")
	if !ok || ac6_2.ParentID != "AC-6" || ac6_2.Kind != control.KindEnhancement || ac6_2.Status != control.StatusActive {
		t.Fatalf("AC-6(2) mismatch: %+v", ac6_2)
	}

	ac7, ok := cat.Get("AC-7")
	if !ok || ac7.Title != "Unsuccessful Logon Attempts" || ac7.Kind != control.KindControl || ac7.Status != control.StatusActive {
		t.Fatalf("AC-7 mismatch: %+v", ac7)
	}

	// Test withdrawn control with multiple references
	ac13, ok := cat.Get("AC-13")
	if !ok {
		t.Fatal("AC-13 not found in catalog")
	}
	if ac13.Status != control.StatusWithdrawn {
		t.Errorf("AC-13 Status = %q, want %q", ac13.Status, control.StatusWithdrawn)
	}
	if len(ac13.References) != 2 {
		t.Fatalf("AC-13 References count = %d, want 2", len(ac13.References))
	}
	if ac13.References[0].ID != "AC-2" || ac13.References[0].Relation != "incorporated-into" {
		t.Errorf("AC-13 Reference[0] mismatch: %+v", ac13.References[0])
	}
	if ac13.References[1].ID != "AU-6" || ac13.References[1].Relation != "incorporated-into" {
		t.Errorf("AC-13 Reference[1] mismatch: %+v", ac13.References[1])
	}

	// Test withdrawn control without references
	sc19, ok := cat.Get("SC-19")
	if !ok {
		t.Fatal("SC-19 not found in catalog")
	}
	if sc19.Status != control.StatusWithdrawn {
		t.Errorf("SC-19 Status = %q, want %q", sc19.Status, control.StatusWithdrawn)
	}
	if len(sc19.References) != 0 {
		t.Errorf("SC-19 expected 0 references, got %d", len(sc19.References))
	}
}

func TestNormalize_StatusAndReferences(t *testing.T) {
	tests := []struct {
		name       string
		props      []nist.Property
		links      []nist.Link
		wantStatus control.Status
		wantRefs   []control.Reference
		wantErr    bool
	}{
		{
			name:       "absent status defaults to active",
			props:      nil,
			wantStatus: control.StatusActive,
		},
		{
			name: "explicit withdrawn status",
			props: []nist.Property{
				{Name: "status", Value: "withdrawn"},
			},
			wantStatus: control.StatusWithdrawn,
		},
		{
			name: "unknown explicit status returns error",
			props: []nist.Property{
				{Name: "status", Value: "retired"},
			},
			wantErr: true,
		},
		{
			name: "incorporated-into and moved-to links",
			props: []nist.Property{
				{Name: "status", Value: "withdrawn"},
			},
			links: []nist.Link{
				{Rel: "incorporated-into", Href: "#ac-2"},
				{Rel: "moved-to", Href: "#sc-7"},
				{Rel: "related", Href: "#ia-1"}, // Should be ignored
			},
			wantStatus: control.StatusWithdrawn,
			wantRefs: []control.Reference{
				{ID: "AC-2", Relation: "incorporated-into"},
				{ID: "SC-7", Relation: "moved-to"},
			},
		},
		{
			name: "statement-level reference resolves to parent control",
			props: []nist.Property{
				{Name: "status", Value: "withdrawn"},
			},
			links: []nist.Link{
				{Rel: "incorporated-into", Href: "#ac-2_smt.k"},
			},
			wantStatus: control.StatusWithdrawn,
			wantRefs: []control.Reference{
				{ID: "AC-2", Relation: "incorporated-into"},
			},
		},
		{
			name: "family group reference accepted for target",
			props: []nist.Property{
				{Name: "status", Value: "withdrawn"},
			},
			links: []nist.Link{
				{Rel: "incorporated-into", Href: "#sr"},
			},
			wantStatus: control.StatusWithdrawn,
			wantRefs: []control.Reference{
				{ID: "SR", Relation: "incorporated-into"},
			},
		},
		{
			name: "malformed href missing hash",
			props: []nist.Property{
				{Name: "status", Value: "withdrawn"},
			},
			links: []nist.Link{
				{Rel: "incorporated-into", Href: "ac-2"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := nist.Document{
				Catalog: nist.Catalog{
					Metadata: nist.Metadata{Title: "NIST SP 800-53 Rev. 5 Test", Version: "5.2.0"},
					Groups: []nist.Group{
						{
							Title: "Test Family",
							Controls: []nist.Control{
								{
									ID:    "ac-1",
									Title: "Test Control",
									Props: tt.props,
									Links: tt.links,
								},
							},
						},
					},
				},
			}

			cat, err := nist.Normalize(doc)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got success: %+v", cat)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			ctrl := cat.Controls[0]
			if ctrl.Status != tt.wantStatus {
				t.Errorf("Status = %q, want %q", ctrl.Status, tt.wantStatus)
			}
			if len(ctrl.References) != len(tt.wantRefs) {
				t.Fatalf("References count = %d, want %d", len(ctrl.References), len(tt.wantRefs))
			}
			for i, wantRef := range tt.wantRefs {
				if ctrl.References[i] != wantRef {
					t.Errorf("Ref[%d] = %+v, want %+v", i, ctrl.References[i], wantRef)
				}
			}
		})
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
		{"sr", "", true},       // family group ID cannot be a control ID
		{"ac-06.02", "", true}, // leading zero
		{"ac-06", "", true},    // leading zero
		{"ac6.2", "", true},    // missing hyphen
		{"AC_06", "", true},    // wrong case & underscore
		{"", "", true},         // empty
	}

	for _, tt := range tests {
		doc := nist.Document{
			Catalog: nist.Catalog{
				Metadata: nist.Metadata{Title: "NIST SP 800-53 Rev 5 Test", Version: "5.2.0"},
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

func TestNormalize_DocumentIdentity(t *testing.T) {
	tests := []struct {
		name    string
		title   string
		version string
		wantErr bool
	}{
		{
			name:    "official title pattern accepted",
			title:   "Electronic (OSCAL) Version of NIST SP 800-53 Rev 5.2.0 Controls",
			version: "5.2.0",
			wantErr: false,
		},
		{
			name:    "test fixture title with Rev. 5 accepted",
			title:   "NIST SP 800-53 Rev. 5 Small Test Fixture",
			version: "5.2.0",
			wantErr: false,
		},
		{
			name:    "unrelated catalog title rejected",
			title:   "FedRAMP Low Baseline Catalog",
			version: "5.2.0",
			wantErr: true,
		},
		{
			name:    "missing rev 5 in title rejected",
			title:   "NIST SP 800-53 Controls",
			version: "5.2.0",
			wantErr: true,
		},
		{
			name:    "non-5.x version rejected",
			title:   "NIST SP 800-53 Rev 5 Catalog",
			version: "4.0.0",
			wantErr: true,
		},
		{
			name:    "empty version rejected",
			title:   "NIST SP 800-53 Rev 5 Catalog",
			version: "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := nist.Document{
				Catalog: nist.Catalog{
					Metadata: nist.Metadata{Title: tt.title, Version: tt.version},
					Groups: []nist.Group{
						{
							Title: "Access Control",
							Controls: []nist.Control{
								{ID: "ac-1", Title: "Policy"},
							},
						},
					},
				},
			}
			_, err := nist.Normalize(doc)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Normalize() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestNormalize_EmptyRelease(t *testing.T) {
	doc := nist.Document{
		Catalog: nist.Catalog{
			Metadata: nist.Metadata{Title: "NIST SP 800-53 Rev 5 Test", Version: "   "},
		},
	}
	_, err := nist.Normalize(doc)
	if err == nil {
		t.Fatal("expected error for empty metadata version, got nil")
	}
}

func TestNormalize_EmptyGroupsOrControls(t *testing.T) {
	// Document with empty groups: []
	docEmptyGroups := nist.Document{
		Catalog: nist.Catalog{
			Metadata: nist.Metadata{Title: "NIST SP 800-53 Rev 5 Test", Version: "5.2.0"},
			Groups:   []nist.Group{},
		},
	}
	if _, err := nist.Normalize(docEmptyGroups); err == nil {
		t.Fatal("expected error for empty groups, got nil")
	}

	// Document with group but empty controls: []
	docEmptyControls := nist.Document{
		Catalog: nist.Catalog{
			Metadata: nist.Metadata{Title: "NIST SP 800-53 Rev 5 Test", Version: "5.2.0"},
			Groups: []nist.Group{
				{Title: "Access Control", Controls: []nist.Control{}},
			},
		},
	}
	if _, err := nist.Normalize(docEmptyControls); err == nil {
		t.Fatal("expected error for empty controls, got nil")
	}
}
