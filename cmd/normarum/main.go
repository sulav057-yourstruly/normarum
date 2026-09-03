package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"normarum/internal/core"
	"normarum/internal/frameworks/nist80053"
	"normarum/internal/storage"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultCatalogPath = "data/catalog.json"

	ExitSuccess      = 0
	ExitVerifyFail   = 1
	ExitProgramError = 2
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(ExitProgramError)
	}

	var code int
	switch os.Args[1] {
	case "import":
		code = runImport(os.Args[2:])
	case "get":
		code = runGet(os.Args[2:])
	case "search":
		code = runSearch(os.Args[2:])
	case "verify":
		code = runVerify(os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
		code = ExitSuccess
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command %q\n\n", os.Args[1])
		printUsage()
		code = ExitProgramError
	}

	os.Exit(code)
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `normarum v0.1.0 — Authoritative Security Control Reference Tool

Usage:
  normarum <command> [arguments]

Commands:
  import <file>                    Import official NIST SP 800-53 OSCAL JSON catalog
  get [--source <file>] <id>       Get official control details by ID
  search <query>                   Search controls by ID or title
  verify <id> [title]              Verify control existence and optional title match
`)
}

// loadSource reads, hashes, parses, normalizes, attaches provenance, and validates
// an authoritative OSCAL source file in a single-read flow.
// Both 'normarum import' and 'normarum get --source' enforce this trust boundary.
func loadSource(path string) (core.Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return core.Catalog{}, fmt.Errorf("read source file %q: %w", path, err)
	}

	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])

	doc, err := nist80053.Parse(bytes.NewReader(data))
	if err != nil {
		return core.Catalog{}, fmt.Errorf("parse source %q: %w", path, err)
	}

	cat, err := nist80053.Normalize(doc)
	if err != nil {
		return core.Catalog{}, fmt.Errorf("normalize source %q: %w", path, err)
	}

	cat.Source.ImportedFrom = filepath.ToSlash(path)
	cat.Source.SHA256 = hash

	if err := cat.Validate(); err != nil {
		return core.Catalog{}, fmt.Errorf("validate source %q: %w", path, err)
	}

	return cat, nil
}

// loadSourceBackedCatalog enforces the source-backed verification trust model.
// The local catalog file (e.g. data/catalog.json) is treated strictly as a cache.
// For verification, it loads cached provenance metadata, reads the raw source at ImportedFrom,
// verifies that SHA-256 matches the stored fingerprint, and constructs a fresh catalog
// from the raw bytes. If the raw source is missing or modified, it halts with an integrity error.
func loadSourceBackedCatalog(catalogPath string) (core.Catalog, error) {
	cached, err := storage.Load(catalogPath)
	if err != nil {
		return core.Catalog{}, fmt.Errorf("load cached catalog from %q: %w\n(Run 'normarum import <file>' first)", catalogPath, err)
	}

	if cached.Source.ImportedFrom == "" || cached.Source.SHA256 == "" {
		return core.Catalog{}, fmt.Errorf("cached catalog %q lacks source provenance metadata\n(Re-run 'normarum import <file>')", catalogPath)
	}

	rawBytes, err := os.ReadFile(cached.Source.ImportedFrom)
	if err != nil {
		return core.Catalog{}, fmt.Errorf("authoritative source file %q unavailable for verification: %w", cached.Source.ImportedFrom, err)
	}

	sum := sha256.Sum256(rawBytes)
	rawHash := hex.EncodeToString(sum[:])
	if rawHash != cached.Source.SHA256 {
		return core.Catalog{}, fmt.Errorf("authoritative source %q integrity verification failed:\n  expected SHA-256: %s\n  computed SHA-256: %s\n(Source file was modified after import)",
			cached.Source.ImportedFrom, cached.Source.SHA256, rawHash)
	}

	doc, err := nist80053.Parse(bytes.NewReader(rawBytes))
	if err != nil {
		return core.Catalog{}, fmt.Errorf("parse authoritative source %q: %w", cached.Source.ImportedFrom, err)
	}

	cat, err := nist80053.Normalize(doc)
	if err != nil {
		return core.Catalog{}, fmt.Errorf("normalize authoritative source %q: %w", cached.Source.ImportedFrom, err)
	}

	cat.Source.ImportedFrom = cached.Source.ImportedFrom
	cat.Source.SHA256 = rawHash

	if err := cat.Validate(); err != nil {
		return core.Catalog{}, fmt.Errorf("validate authoritative source %q: %w", cached.Source.ImportedFrom, err)
	}

	return cat, nil
}

func runImport(args []string) int {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitSuccess
		}
		return ExitProgramError
	}

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "Error: import requires exactly one OSCAL JSON file path")
		fmt.Fprintln(os.Stderr, "Usage: normarum import <file>")
		return ExitProgramError
	}

	sourcePath := fs.Arg(0)
	cat, err := loadSource(sourcePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return ExitProgramError
	}

	if err := storage.Save(defaultCatalogPath, &cat); err != nil {
		fmt.Fprintf(os.Stderr, "Error: save catalog: %v\n", err)
		return ExitProgramError
	}

	fmt.Printf("Imported %s %s Rev. %s\nControls: %d\nOutput: %s\n",
		cat.Source.Authority,
		cat.Source.Standard,
		cat.Source.Revision,
		len(cat.Controls),
		defaultCatalogPath,
	)
	return ExitSuccess
}

func runGet(args []string) int {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	sourceFile := fs.String("source", "", "read directly from OSCAL source file (debug/first-slice convenience)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitSuccess
		}
		return ExitProgramError
	}

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "Error: get requires exactly one control ID")
		fmt.Fprintln(os.Stderr, "Usage: normarum get [--source <file>] <control-id>")
		return ExitProgramError
	}

	controlID := fs.Arg(0)

	var cat core.Catalog
	if *sourceFile != "" {
		var err error
		cat, err = loadSource(*sourceFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return ExitProgramError
		}
	} else {
		var err error
		cat, err = storage.Load(defaultCatalogPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: load catalog from %q: %v\n(Run 'normarum import <file>' first)\n", defaultCatalogPath, err)
			return ExitProgramError
		}
		if err := cat.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: catalog validation failed: %v\n", err)
			return ExitProgramError
		}
	}

	ctrl, ok := cat.Get(controlID)
	if !ok {
		fmt.Fprintf(os.Stderr, "Control %q not found in catalog\n", controlID)
		return ExitVerifyFail
	}

	// Format output explainably
	fmt.Printf("%s %s Rev. %s\n\n",
		cat.Source.Authority,
		cat.Source.Standard,
		cat.Source.Revision,
	)

	if ctrl.Kind == core.KindEnhancement {
		parentTitle := "Unknown"
		if parent, pOK := cat.Get(ctrl.ParentID); pOK {
			parentTitle = parent.Title
		}
		fmt.Printf("%s\n%s\n\nParent:\n%s — %s\n",
			ctrl.ID,
			ctrl.Title,
			ctrl.ParentID,
			parentTitle,
		)
	} else {
		if ctrl.Status == core.StatusWithdrawn {
			fmt.Printf("%s\n%s\n", ctrl.ID, ctrl.Title)
		} else {
			fmt.Printf("%s — %s\n", ctrl.ID, ctrl.Title)
		}
	}

	if ctrl.Status == core.StatusWithdrawn {
		fmt.Println("\nStatus: WITHDRAWN")
		if len(ctrl.References) > 0 {
			printReferences(ctrl.References)
		}
	}

	fmt.Printf("\nFamily: %s\nType: %s\n", ctrl.Family, formatKind(ctrl.Kind))
	return ExitSuccess
}

func formatKind(k core.Kind) string {
	switch k {
	case core.KindEnhancement:
		return "Enhancement"
	default:
		return "Control"
	}
}

func runSearch(args []string) int {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitSuccess
		}
		return ExitProgramError
	}

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "Error: search requires exactly one search query")
		fmt.Fprintln(os.Stderr, "Usage: normarum search <query>")
		return ExitProgramError
	}

	query := fs.Arg(0)
	if strings.TrimSpace(query) == "" {
		fmt.Fprintln(os.Stderr, "Error: search query must not be empty")
		return ExitProgramError
	}

	cat, err := storage.Load(defaultCatalogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: load catalog: %v\n(Run 'normarum import <file>' first)\n", err)
		return ExitProgramError
	}

	if err := cat.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: catalog validation failed: %v\n", err)
		return ExitProgramError
	}

	matches := cat.Search(query)
	if len(matches) == 0 {
		fmt.Printf("No controls matching %q found.\n", query)
		return ExitSuccess
	}

	fmt.Printf("Matches:\n\n")
	for i, m := range matches {
		if i > 0 {
			fmt.Println()
		}
		if m.Status == core.StatusWithdrawn {
			fmt.Printf("%s\n%s [WITHDRAWN]\n", m.ID, m.Title)
		} else {
			fmt.Printf("%s\n%s\n", m.ID, m.Title)
		}
	}

	return ExitSuccess
}

func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitSuccess
		}
		return ExitProgramError
	}

	if fs.NArg() < 1 || fs.NArg() > 2 {
		fmt.Fprintln(os.Stderr, "Error: verify requires a control ID and an optional title (multi-word titles must be enclosed in quotes)")
		fmt.Fprintln(os.Stderr, "Usage: normarum verify <control-id> [title]")
		return ExitProgramError
	}

	controlID := fs.Arg(0)
	var expectedTitle *string
	if fs.NArg() == 2 {
		t := fs.Arg(1)
		expectedTitle = &t
	}

	cat, err := loadSourceBackedCatalog(defaultCatalogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return ExitProgramError
	}

	res := cat.Verify(controlID, expectedTitle)

	// Decision 1: Non-canonical reference cited
	if res.NonCanonical {
		fmt.Printf("FAIL\n\nControl reference %q is not in canonical authoritative form.\n\nCanonical identifier:\n%s\n",
			res.ID,
			res.CanonicalID,
		)
		return ExitVerifyFail
	}

	// Decision 2: Unknown control
	if !res.Exists {
		fmt.Printf("FAIL\n\nUnknown control:\n%s\n", res.ID)
		return ExitVerifyFail
	}

	// Decision 3: Withdrawn control
	if res.Status == core.StatusWithdrawn {
		fmt.Printf("FAIL\n\n%s — %s\n\nStatus: WITHDRAWN\n", res.ID, res.OfficialTitle)
		if len(res.References) > 0 {
			printReferences(res.References)
		}
		return ExitVerifyFail
	}

	// Decision 4: Title mismatch
	if res.TitleChecked && !res.TitleMatches {
		fmt.Printf("FAIL\n\n%s\n\nTitle mismatch.\n\nProvided:\n%s\n\nOfficial:\n%s\n",
			res.ID,
			res.ProvidedTitle,
			res.OfficialTitle,
		)
		return ExitVerifyFail
	}

	// Decision 5: PASS (Mode 1 - title not checked)
	if !res.TitleChecked {
		fmt.Printf("PASS\n\n%s — %s\nTitle not checked.\n",
			res.ID,
			res.OfficialTitle,
		)
		return ExitSuccess
	}

	// Decision 5: PASS (Mode 2 - title matches exactly)
	fmt.Printf("PASS\n\n%s — %s\nExact match.\n",
		res.ID,
		res.OfficialTitle,
	)
	return ExitSuccess
}

func printReferences(refs []core.Reference) {
	grouped := make(map[string][]string)
	var order []string
	for _, r := range refs {
		if _, seen := grouped[r.Relation]; !seen {
			order = append(order, r.Relation)
		}
		grouped[r.Relation] = append(grouped[r.Relation], r.ID)
	}

	for _, rel := range order {
		ids := grouped[rel]
		header := formatRelationHeader(rel)
		fmt.Printf("\n%s\n", header)
		for _, id := range ids {
			fmt.Println(id)
		}
	}
}

func formatRelationHeader(rel string) string {
	switch rel {
	case "incorporated-into":
		return "Incorporated into:"
	case "moved-to":
		return "Moved to:"
	default:
		words := strings.Split(rel, "-")
		for i, w := range words {
			if w != "" {
				words[i] = strings.ToUpper(w[:1]) + w[1:]
			}
		}
		return strings.Join(words, " ") + ":"
	}
}
