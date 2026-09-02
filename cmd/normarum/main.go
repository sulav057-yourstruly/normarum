package main

import (
	"flag"
	"fmt"
	"normarum/internal/control"
	"normarum/internal/nist"
	"normarum/internal/storage"
	"os"
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
	fmt.Fprintf(os.Stderr, `normarum V0.1 — Authoritative Security Control Reference Tool

Usage:
  normarum <command> [arguments]

Commands:
  import <file>                    Import official NIST SP 800-53 OSCAL JSON catalog
  get [--source <file>] <id>       Get official control details by ID
  search <query>                   Search controls by ID or title
  verify <id> [title]              Verify control existence and optional title match
`)
}

func runImport(args []string) int {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return ExitProgramError
	}

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: import requires an OSCAL JSON file path")
		fmt.Fprintln(os.Stderr, "Usage: normarum import <file>")
		return ExitProgramError
	}

	sourcePath := fs.Arg(0)
	f, err := os.Open(sourcePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: open source file %q: %v\n", sourcePath, err)
		return ExitProgramError
	}
	defer f.Close()

	doc, err := nist.Parse(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return ExitProgramError
	}

	cat, err := nist.Normalize(doc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return ExitProgramError
	}

	if err := cat.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: catalog validation failed: %v\n", err)
		return ExitProgramError
	}

	if err := storage.Save(defaultCatalogPath, cat); err != nil {
		fmt.Fprintf(os.Stderr, "Error: save catalog: %v\n", err)
		return ExitProgramError
	}

	fmt.Printf("Imported %s Rev. %s\nRelease: %s\n\nControls: %d\nOutput: %s\n",
		cat.Source.Framework,
		cat.Source.Revision,
		cat.Source.Release,
		len(cat.Controls),
		defaultCatalogPath,
	)
	return ExitSuccess
}

func runGet(args []string) int {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	sourceFile := fs.String("source", "", "read directly from OSCAL source file (debug/first-slice convenience)")

	if err := fs.Parse(args); err != nil {
		return ExitProgramError
	}

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: get requires a control ID")
		fmt.Fprintln(os.Stderr, "Usage: normarum get [--source <file>] <control-id>")
		return ExitProgramError
	}

	controlID := fs.Arg(0)
	var cat control.Catalog

	if *sourceFile != "" {
		f, err := os.Open(*sourceFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: open source file %q: %v\n", *sourceFile, err)
			return ExitProgramError
		}
		defer f.Close()

		doc, err := nist.Parse(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return ExitProgramError
		}

		cat, err = nist.Normalize(doc)
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
	}

	if err := cat.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: catalog validation failed: %v\n", err)
		return ExitProgramError
	}

	ctrl, ok := cat.Get(controlID)
	if !ok {
		fmt.Fprintf(os.Stderr, "Control %q not found in catalog\n", controlID)
		return ExitVerifyFail
	}

	// Format output explainably
	fmt.Printf("%s Rev. %s\nRelease: %s\n\n",
		cat.Source.Framework,
		cat.Source.Revision,
		cat.Source.Release,
	)

	if ctrl.Kind == control.KindEnhancement {
		parentTitle := "Unknown"
		if parent, pOK := cat.Get(ctrl.ParentID); pOK {
			parentTitle = parent.Title
		}
		fmt.Printf("%s\n%s\n\nParent:\n%s — %s\n\nFamily: %s\nType: Enhancement\n",
			ctrl.ID,
			ctrl.Title,
			ctrl.ParentID,
			parentTitle,
			ctrl.Family,
		)
	} else {
		fmt.Printf("%s — %s\n\nFamily: %s\nType: Control\n",
			ctrl.ID,
			ctrl.Title,
			ctrl.Family,
		)
	}

	return ExitSuccess
}

func runSearch(args []string) int {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return ExitProgramError
	}

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: search requires a query string")
		fmt.Fprintln(os.Stderr, "Usage: normarum search <query>")
		return ExitProgramError
	}

	query := strings.TrimSpace(fs.Arg(0))
	if query == "" {
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

	fmt.Println("Matches:")
	for _, m := range matches {
		fmt.Printf("\n%s\n%s\n", m.ID, m.Title)
	}

	return ExitSuccess
}

func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return ExitProgramError
	}

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: verify requires at least a control ID")
		fmt.Fprintln(os.Stderr, "Usage: normarum verify <control-id> [title]")
		return ExitProgramError
	}

	controlID := fs.Arg(0)
	var expectedTitle string
	if fs.NArg() >= 2 {
		expectedTitle = fs.Arg(1)
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

	res := cat.Verify(controlID, expectedTitle)

	if !res.Exists {
		fmt.Printf("FAIL\n\nUnknown control:\n%s\n\nSource:\n%s Rev. %s\nRelease %s\n",
			res.ID,
			cat.Source.Framework,
			cat.Source.Revision,
			cat.Source.Release,
		)
		return ExitVerifyFail
	}

	if !res.TitleChecked {
		// Existence only mode
		fmt.Printf("PASS\n\nControl: %s\n\n✓ Control exists\n\nOfficial title:\n%s\n\nSource:\n%s Rev. %s\nRelease %s\n",
			res.ID,
			res.OfficialTitle,
			cat.Source.Framework,
			cat.Source.Revision,
			cat.Source.Release,
		)
		return ExitSuccess
	}

	if !res.TitleMatches {
		// Title check failed
		fmt.Printf("FAIL\n\nControl %s exists, but the title does not match.\n\nProvided:\n%s\n\nOfficial:\n%s\n\nSource:\n%s Rev. %s\nRelease %s\n",
			res.ID,
			res.ProvidedTitle,
			res.OfficialTitle,
			cat.Source.Framework,
			cat.Source.Revision,
			cat.Source.Release,
		)
		return ExitVerifyFail
	}

	// Title check passed
	fmt.Printf("PASS\n\nControl: %s\n\n✓ Control exists\n✓ Title matches\n\nOfficial title:\n%s\n\nSource:\n%s Rev. %s\nRelease %s\n",
		res.ID,
		res.OfficialTitle,
		cat.Source.Framework,
		cat.Source.Revision,
		cat.Source.Release,
	)
	return ExitSuccess
}
