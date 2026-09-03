package nist80053_test

import (
	"normarum/internal/frameworks/nist80053"
	"os"
	"strings"
	"testing"
)

func TestParseBaseline_ValidFixture(t *testing.T) {
	f, err := os.Open("../../../testdata/nist-baseline-small.json")
	if err != nil {
		t.Fatalf("failed to open test fixture: %v", err)
	}
	defer f.Close()

	doc, err := nist80053.ParseBaseline(f)
	if err != nil {
		t.Fatalf("ParseBaseline failed: %v", err)
	}

	if doc.Profile.Metadata.Version != "5.2.0" {
		t.Errorf("Metadata.Version = %q, want %q", doc.Profile.Metadata.Version, "5.2.0")
	}

	ids := doc.ExtractBaselineControlIDs()
	if len(ids) != 4 {
		t.Fatalf("ExtractBaselineControlIDs len = %d, want 4", len(ids))
	}

	expected := []string{"ac-1", "ac-2", "ac-6", "ac-6.2"}
	for i, want := range expected {
		if ids[i] != want {
			t.Errorf("ids[%d] = %q, want %q", i, ids[i], want)
		}
	}
}

func TestParseBaseline_RealLowProfile(t *testing.T) {
	f, err := os.Open("../../../data/raw/nist/sp800-53/rev5/baselines/NIST_SP-800-53_rev5_LOW-baseline_profile.json")
	if err != nil {
		t.Skip("skipping real low profile test if file missing")
	}
	defer f.Close()

	doc, err := nist80053.ParseBaseline(f)
	if err != nil {
		t.Fatalf("ParseBaseline on real low profile failed: %v", err)
	}

	ids := doc.ExtractBaselineControlIDs()
	if len(ids) == 0 {
		t.Fatal("expected non-empty control IDs from real low profile")
	}
}

func TestParseBaseline_InvalidJSON(t *testing.T) {
	_, err := nist80053.ParseBaseline(strings.NewReader("{not-valid-json"))
	if err == nil {
		t.Fatal("expected error on invalid JSON, got nil")
	}
}

func TestParseBaseline_NilReader(t *testing.T) {
	_, err := nist80053.ParseBaseline(nil)
	if err == nil {
		t.Fatal("expected error on nil reader, got nil")
	}
}

func TestParseBaseline_TrailingData(t *testing.T) {
	validWithTrailing := `{"profile":{"metadata":{"version":"5.2.0"}}} {"unexpected": "trailing"}`
	_, err := nist80053.ParseBaseline(strings.NewReader(validWithTrailing))
	if err == nil {
		t.Fatal("expected error on trailing data after document, got nil")
	}
}
