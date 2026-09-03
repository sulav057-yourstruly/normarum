package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"normarum/internal/control"
	"normarum/internal/storage"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// captureOutput intercepts os.Stdout during the execution of fn and returns the captured output.
func captureOutput(fn func()) string {
	r, w, err := os.Pipe()
	if err != nil {
		fn()
		return ""
	}
	oldStdout := os.Stdout
	os.Stdout = w

	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		outC <- buf.String()
	}()

	fn()
	_ = w.Close()
	os.Stdout = oldStdout
	return <-outC
}

// captureStderr intercepts os.Stderr during the execution of fn and returns the captured output.
func captureStderr(fn func()) string {
	r, w, err := os.Pipe()
	if err != nil {
		fn()
		return ""
	}
	oldStderr := os.Stderr
	os.Stderr = w

	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		outC <- buf.String()
	}()

	fn()
	_ = w.Close()
	os.Stderr = oldStderr
	return <-outC
}

const smallTestOSCAL = `{
	"catalog": {
		"metadata": {"title": "NIST SP 800-53 Rev. 5 Small Test Fixture", "version": "5.2.0"},
		"groups": [
			{
				"id": "ac",
				"title": "Access Control",
				"controls": [
					{
						"id": "ac-6",
						"title": "Least Privilege",
						"controls": [
							{
								"id": "ac-6.2",
								"title": "Non-privileged Access for Nonsecurity Functions"
							}
						]
					},
					{
						"id": "ac-13",
						"title": "Supervision and Review — Access Control",
						"props": [{"name": "status", "value": "withdrawn"}],
						"links": [{"rel": "incorporated-into", "href": "#ac-6"}]
					}
				]
			},
			{
				"id": "sc",
				"title": "System and Communications Protection",
				"controls": [
					{
						"id": "sc-19",
						"title": "Voice Over Internet Protocol",
						"props": [{"name": "status", "value": "withdrawn"}]
					}
				]
			}
		]
	}
}`

func createTestEnvironment(t *testing.T) (rawPath, catPath string) {
	t.Helper()
	rawPath = filepath.Join(t.TempDir(), "source.json")
	if err := os.WriteFile(rawPath, []byte(smallTestOSCAL), 0o644); err != nil {
		t.Fatalf("failed to write raw source: %v", err)
	}

	sum := sha256.Sum256([]byte(smallTestOSCAL))
	rawHash := hex.EncodeToString(sum[:])

	cat := control.Catalog{
		Source: control.Source{
			Authority:    "NIST",
			Standard:     "SP 800-53",
			Revision:     "5",
			Release:      "5.2.0",
			ImportedFrom: filepath.ToSlash(rawPath),
			SHA256:       rawHash,
			ImportedAt:   time.Now().UTC(),
		},
		Controls: []control.Control{
			{
				ID:     "AC-6",
				Title:  "Least Privilege",
				Family: "Access Control",
				Kind:   control.KindControl,
				Status: control.StatusActive,
			},
			{
				ID:       "AC-6(2)",
				Title:    "Non-privileged Access for Nonsecurity Functions",
				Family:   "Access Control",
				ParentID: "AC-6",
				Kind:     control.KindEnhancement,
				Status:   control.StatusActive,
			},
			{
				ID:     "AC-13",
				Title:  "Supervision and Review — Access Control",
				Family: "Access Control",
				Kind:   control.KindControl,
				Status: control.StatusWithdrawn,
				References: []control.Reference{
					{ID: "AC-6", Relation: "incorporated-into"},
				},
			},
			{
				ID:     "SC-19",
				Title:  "Voice Over Internet Protocol",
				Family: "System and Communications Protection",
				Kind:   control.KindControl,
				Status: control.StatusWithdrawn,
			},
		},
	}

	catPath = "data/catalog.json"
	if err := storage.Save(catPath, &cat); err != nil {
		t.Fatalf("failed to create test catalog: %v", err)
	}

	return rawPath, catPath
}

func TestCLIGet_WithSourceDirect(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "testdata", "nist-small.json")
	var out string
	code := 0

	out = captureOutput(func() {
		code = runGet([]string{"--source", fixturePath, "AC-6"})
	})
	if code != ExitSuccess {
		t.Errorf("runGet returned %d, want %d", code, ExitSuccess)
	}
	if !strings.Contains(out, "Least Privilege") {
		t.Errorf("expected output to contain 'Least Privilege', got: %s", out)
	}

	out = captureOutput(func() {
		code = runGet([]string{"--source", fixturePath, "ac-6"})
	})
	if code != ExitSuccess {
		t.Errorf("runGet forgiving lookup returned %d, want %d", code, ExitSuccess)
	}
	if !strings.Contains(out, "Least Privilege") {
		t.Errorf("expected output to contain 'Least Privilege', got: %s", out)
	}

	out = captureOutput(func() {
		code = runGet([]string{"--source", fixturePath, "AC-6(2)"})
	})
	if code != ExitSuccess {
		t.Errorf("runGet for enhancement returned %d, want %d", code, ExitSuccess)
	}
	if !strings.Contains(out, "Enhancement") {
		t.Errorf("expected output to contain 'Enhancement', got: %s", out)
	}

	out = captureOutput(func() {
		code = runGet([]string{"--source", fixturePath, "AC-13"})
	})
	if code != ExitSuccess {
		t.Errorf("runGet for withdrawn control returned %d, want %d", code, ExitSuccess)
	}
	if !strings.Contains(out, "Status: WITHDRAWN") {
		t.Errorf("expected output to contain 'Status: WITHDRAWN', got: %s", out)
	}
	if !strings.Contains(out, "Incorporated into:") {
		t.Errorf("expected output to contain 'Incorporated into:', got: %s", out)
	}
	if !strings.Contains(out, "AC-2") || !strings.Contains(out, "AU-6") {
		t.Errorf("expected output to contain AC-2 and AU-6, got: %s", out)
	}

	code = runGet([]string{"--source", fixturePath, "AC-99"})
	if code != ExitVerifyFail {
		t.Errorf("runGet for missing control returned %d, want %d", code, ExitVerifyFail)
	}
}

func TestCLIGet_WithSourceDirect_ValidationEnforced(t *testing.T) {
	invalidOSCAL := `{
		"catalog": {
			"metadata": {"title": "NIST SP 800-53 Rev 5 Invalid Test", "version": "5.2.0"},
			"groups": [{
				"id": "ac",
				"title": "Access Control",
				"controls": [{
					"id": "ac-13",
					"title": "Supervision",
					"props": [{"name": "status", "value": "withdrawn"}],
					"links": [{"rel": "incorporated-into", "href": "#ac-99"}]
				}]
			}]
		}
	}`

	tempDir := t.TempDir()
	invalidPath := filepath.Join(tempDir, "invalid.json")
	if err := os.WriteFile(invalidPath, []byte(invalidOSCAL), 0o644); err != nil {
		t.Fatalf("failed to write invalid oscal: %v", err)
	}

	code := runGet([]string{"--source", invalidPath, "AC-13"})
	if code != ExitProgramError {
		t.Errorf("expected ExitProgramError (%d) on catalog validation failure, got %d", ExitProgramError, code)
	}
}

func TestLoadSource_HashMatchesExactBytes(t *testing.T) {
	fixtureContent := []byte(`{
		"catalog": {
			"metadata": {"title": "NIST SP 800-53 Rev. 5 Byte Hash Fixture", "version": "5.2.0"},
			"groups": [{
				"id": "ac",
				"title": "Access Control",
				"controls": [{
					"id": "ac-1",
					"title": "Policy"
				}]
			}]
		}
	}`)

	tempDir := t.TempDir()
	fixturePath := filepath.Join(tempDir, "fixture.json")
	if err := os.WriteFile(fixturePath, fixtureContent, 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	expectedSum := sha256.Sum256(fixtureContent)
	expectedHex := hex.EncodeToString(expectedSum[:])

	cat, err := loadSource(fixturePath)
	if err != nil {
		t.Fatalf("loadSource failed: %v", err)
	}

	if cat.Source.SHA256 != expectedHex {
		t.Errorf("Artifact SHA-256 = %q, want %q", cat.Source.SHA256, expectedHex)
	}
}

func TestCLIGet_MissingArgs(t *testing.T) {
	code := runGet([]string{})
	if code != ExitProgramError {
		t.Errorf("expected ExitProgramError for missing args, got %d", code)
	}
}

func TestCLISearch_EmptyQuery(t *testing.T) {
	code := runSearch([]string{""})
	if code != ExitProgramError {
		t.Errorf("expected ExitProgramError for empty query, got %d", code)
	}

	code = runSearch([]string{"   "})
	if code != ExitProgramError {
		t.Errorf("expected ExitProgramError for whitespace query, got %d", code)
	}
}

func TestCLIVerify_MissingArgs(t *testing.T) {
	code := runVerify([]string{})
	if code != ExitProgramError {
		t.Errorf("expected ExitProgramError for missing args, got %d", code)
	}
}

func TestCLIImport_MissingFile(t *testing.T) {
	code := runImport([]string{"non_existent_oscal.json"})
	if code != ExitProgramError {
		t.Errorf("expected ExitProgramError for missing file, got %d", code)
	}
}

func TestCLI_DefaultCatalogOperations(t *testing.T) {
	tempDir := t.TempDir()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current wd: %v", err)
	}
	defer func() {
		_ = os.Chdir(origWd)
	}()

	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir to tempDir: %v", err)
	}

	createTestEnvironment(t)

	var out string
	var code int

	// Test Get Active
	out = captureOutput(func() {
		code = runGet([]string{"AC-6"})
	})
	if code != ExitSuccess {
		t.Errorf("runGet(AC-6) = %d, want %d", code, ExitSuccess)
	}
	if !strings.Contains(out, "AC-6 — Least Privilege") {
		t.Errorf("runGet(AC-6) unexpected output: %s", out)
	}

	// Test Forgiving Get Active
	out = captureOutput(func() {
		code = runGet([]string{"ac-6"})
	})
	if code != ExitSuccess {
		t.Errorf("runGet(ac-6) = %d, want %d", code, ExitSuccess)
	}
	if !strings.Contains(out, "AC-6 — Least Privilege") {
		t.Errorf("runGet(ac-6) unexpected output: %s", out)
	}

	// Test Get Withdrawn
	out = captureOutput(func() {
		code = runGet([]string{"AC-13"})
	})
	if code != ExitSuccess {
		t.Errorf("runGet(AC-13) = %d, want %d", code, ExitSuccess)
	}
	if !strings.Contains(out, "Status: WITHDRAWN") {
		t.Errorf("expected 'Status: WITHDRAWN' in output: %s", out)
	}
	if !strings.Contains(out, "Incorporated into:") || !strings.Contains(out, "AC-6") {
		t.Errorf("expected references in output: %s", out)
	}

	// Test Get Withdrawn without references
	out = captureOutput(func() {
		code = runGet([]string{"SC-19"})
	})
	if code != ExitSuccess {
		t.Errorf("runGet(SC-19) = %d, want %d", code, ExitSuccess)
	}
	if !strings.Contains(out, "Status: WITHDRAWN") {
		t.Errorf("expected 'Status: WITHDRAWN' in output: %s", out)
	}

	// Test Get Missing
	if code := runGet([]string{"AC-99"}); code != ExitVerifyFail {
		t.Errorf("runGet(AC-99) = %d, want %d", code, ExitVerifyFail)
	}

	// Test Search
	out = captureOutput(func() {
		code = runSearch([]string{"Supervision"})
	})
	if code != ExitSuccess {
		t.Errorf("runSearch('Supervision') = %d, want %d", code, ExitSuccess)
	}
	if !strings.Contains(out, "[WITHDRAWN]") {
		t.Errorf("expected search output to mark [WITHDRAWN], got: %s", out)
	}

	// --- STRICT VERIFICATION TESTS ---

	// Decision 1: Non-canonical reference (FAIL -> Exit 1)
	out = captureOutput(func() {
		code = runVerify([]string{"ac-6"})
	})
	if code != ExitVerifyFail {
		t.Errorf("runVerify(ac-6) = %d, want %d", code, ExitVerifyFail)
	}
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "not in canonical authoritative form") || !strings.Contains(out, "AC-6") {
		t.Errorf("expected non-canonical rejection output, got: %s", out)
	}

	// Decision 1: Non-canonical reference halts before status evaluation
	out = captureOutput(func() {
		code = runVerify([]string{"ac-13"})
	})
	if code != ExitVerifyFail {
		t.Errorf("runVerify(ac-13) = %d, want %d", code, ExitVerifyFail)
	}
	if !strings.Contains(out, "not in canonical authoritative form") || strings.Contains(out, "is withdrawn") {
		t.Errorf("expected non-canonical precedence over withdrawn, got: %s", out)
	}

	// Decision 2: Unknown control (FAIL -> Exit 1)
	out = captureOutput(func() {
		code = runVerify([]string{"AC-99"})
	})
	if code != ExitVerifyFail {
		t.Errorf("runVerify(AC-99) = %d, want %d", code, ExitVerifyFail)
	}
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "Unknown control") {
		t.Errorf("unexpected unknown control output: %s", out)
	}

	// Decision 3: Withdrawn control (FAIL -> Exit 1)
	out = captureOutput(func() {
		code = runVerify([]string{"AC-13"})
	})
	if code != ExitVerifyFail {
		t.Errorf("runVerify(AC-13) = %d, want %d", code, ExitVerifyFail)
	}
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "WITHDRAWN") {
		t.Errorf("expected fail explanation in output: %s", out)
	}
	if !strings.Contains(out, "Incorporated into:") || !strings.Contains(out, "AC-6") {
		t.Errorf("expected references in failure output: %s", out)
	}

	// Decision 4: Explicit empty title supplied (FAIL -> Exit 1)
	out = captureOutput(func() {
		code = runVerify([]string{"AC-6", ""})
	})
	if code != ExitVerifyFail {
		t.Errorf("runVerify(AC-6, \"\") = %d, want %d", code, ExitVerifyFail)
	}
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "Title mismatch.") {
		t.Errorf("expected empty title to fail title match: %s", out)
	}

	// Decision 4: Case-sensitive title mismatch (FAIL -> Exit 1)
	out = captureOutput(func() {
		code = runVerify([]string{"AC-6", "least privilege"})
	})
	if code != ExitVerifyFail {
		t.Errorf("runVerify(AC-6, least privilege) = %d, want %d", code, ExitVerifyFail)
	}
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "Title mismatch.") {
		t.Errorf("expected case mismatch to fail title match: %s", out)
	}

	// Decision 5: Mode 1 PASS (title omitted) -> Exit 0
	out = captureOutput(func() {
		code = runVerify([]string{"AC-6"})
	})
	if code != ExitSuccess {
		t.Errorf("runVerify(AC-6) = %d, want %d", code, ExitSuccess)
	}
	if !strings.Contains(out, "PASS") || !strings.Contains(out, "Title not checked.") || !strings.Contains(out, "AC-6 — Least Privilege") {
		t.Errorf("unexpected Mode 1 verify pass output: %s", out)
	}

	// Decision 5: Mode 2 PASS (exact title match) -> Exit 0
	out = captureOutput(func() {
		code = runVerify([]string{"AC-6", "Least Privilege"})
	})
	if code != ExitSuccess {
		t.Errorf("runVerify(AC-6, Least Privilege) = %d, want %d", code, ExitSuccess)
	}
	if !strings.Contains(out, "PASS") || !strings.Contains(out, "Exact match.") || !strings.Contains(out, "AC-6 — Least Privilege") {
		t.Errorf("unexpected Mode 2 verify pass output: %s", out)
	}
}

func TestCLI_VerifySourceBackedAndTamperIntegrity(t *testing.T) {
	tempDir := t.TempDir()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current wd: %v", err)
	}
	defer func() {
		_ = os.Chdir(origWd)
	}()

	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir to tempDir: %v", err)
	}

	rawPath, catPath := createTestEnvironment(t)

	// Scenario 1: Untouched raw source + exact reference -> PASS (Exit 0)
	var out string
	var code int
	out = captureOutput(func() {
		code = runVerify([]string{"AC-6", "Least Privilege"})
	})
	if code != ExitSuccess || !strings.Contains(out, "Exact match.") {
		t.Fatalf("expected untouched verify to PASS, got code %d, out: %s", code, out)
	}

	// Scenario 2: Tamper data/catalog.json title -> verify must NOT trust fake cached title!
	cached, err := storage.Load(catPath)
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	// Maliciously tamper with the cached title in data/catalog.json
	cached.Controls[0].Title = "Malicious Fake Title"
	if err := storage.Save(catPath, &cached); err != nil {
		t.Fatalf("save tampered catalog: %v", err)
	}

	// Verification with real official title must still PASS because it verifies against the raw source
	out = captureOutput(func() {
		code = runVerify([]string{"AC-6", "Least Privilege"})
	})
	if code != ExitSuccess || !strings.Contains(out, "Exact match.") {
		t.Fatalf("expected verify to ignore tampered catalog.json and PASS against raw source, got %d: %s", code, out)
	}

	// Verification with the fake cached title must FAIL
	out = captureOutput(func() {
		code = runVerify([]string{"AC-6", "Malicious Fake Title"})
	})
	if code != ExitVerifyFail || !strings.Contains(out, "Title mismatch.") {
		t.Fatalf("expected verify with tampered title to FAIL, got %d: %s", code, out)
	}

	// Scenario 3: Modify raw OSCAL after import -> hash mismatch -> Exit 2
	if err := os.WriteFile(rawPath, append([]byte(smallTestOSCAL), ' '), 0o644); err != nil {
		t.Fatalf("failed to mutate raw file: %v", err)
	}
	out = captureOutput(func() {
		code = runVerify([]string{"AC-6"})
	})
	if code != ExitProgramError {
		t.Fatalf("expected ExitProgramError (2) on mutated raw source hash mismatch, got %d", code)
	}

	// Scenario 4: Delete raw OSCAL after import -> verification unavailable -> Exit 2
	if err := os.Remove(rawPath); err != nil {
		t.Fatalf("failed to remove raw source: %v", err)
	}
	out = captureOutput(func() {
		code = runVerify([]string{"AC-6"})
	})
	if code != ExitProgramError {
		t.Fatalf("expected ExitProgramError (2) when raw source is deleted, got %d", code)
	}
}

func TestCLIImport_EmptyGroupsOrControlsRobustness(t *testing.T) {
	tempDir := t.TempDir()

	// Empty groups
	emptyGroupsPath := filepath.Join(tempDir, "empty_groups.json")
	if err := os.WriteFile(emptyGroupsPath, []byte(`{
		"catalog": {
			"metadata": {"title": "NIST SP 800-53 Rev. 5 Empty Groups Test", "version": "5.2.0"},
			"groups": []
		}
	}`), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	code := runImport([]string{emptyGroupsPath})
	if code != ExitProgramError {
		t.Fatalf("expected ExitProgramError (2) on importing empty groups, got %d", code)
	}

	// Empty controls in group
	emptyControlsPath := filepath.Join(tempDir, "empty_controls.json")
	if err := os.WriteFile(emptyControlsPath, []byte(`{
		"catalog": {
			"metadata": {"title": "NIST SP 800-53 Rev. 5 Empty Controls Test", "version": "5.2.0"},
			"groups": [
				{"id": "ac", "title": "Access Control", "controls": []}
			]
		}
	}`), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	code = runImport([]string{emptyControlsPath})
	if code != ExitProgramError {
		t.Fatalf("expected ExitProgramError (2) on importing empty controls, got %d", code)
	}
}

func TestCLI_SubcommandHelpAndExtraArgs(t *testing.T) {
	// 1. Subcommand -h and --help should return ExitSuccess (0)
	for _, sub := range []string{"import", "get", "search", "verify"} {
		for _, flag := range []string{"-h", "--help"} {
			var code int
			captureOutput(func() {
				switch sub {
				case "import":
					code = runImport([]string{flag})
				case "get":
					code = runGet([]string{flag})
				case "search":
					code = runSearch([]string{flag})
				case "verify":
					code = runVerify([]string{flag})
				}
			})
			if code != ExitSuccess {
				t.Errorf("subcommand %s %s exited with %d, want %d", sub, flag, code, ExitSuccess)
			}
		}
	}

	// 2. Extra positional arguments should be rejected with ExitProgramError (2)
	extraTests := []struct {
		name string
		run  func() int
	}{
		{"import extra args", func() int { return runImport([]string{"a.json", "b.json"}) }},
		{"get extra args", func() int { return runGet([]string{"AC-6", "AC-7"}) }},
		{"search extra args", func() int { return runSearch([]string{"query1", "query2"}) }},
		{"verify extra args (unquoted multi-word title)", func() int { return runVerify([]string{"AC-6", "Least", "Privilege"}) }},
	}

	for _, tt := range extraTests {
		var code int
		captureOutput(func() {
			code = tt.run()
		})
		if code != ExitProgramError {
			t.Errorf("%s: got exit code %d, want %d", tt.name, code, ExitProgramError)
		}
	}

	// 3. Banner check
	out := captureStderr(func() {
		printUsage()
	})
	if !strings.Contains(out, "normarum v0.1.0") {
		t.Errorf("expected usage banner to contain 'normarum v0.1.0', got: %s", out)
	}
}
