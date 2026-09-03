package control

import "time"

// Kind distinguishes standard base controls from control enhancements.
type Kind string

const (
	KindControl     Kind = "control"
	KindEnhancement Kind = "enhancement"
)

// Status represents the operational or lifecycle status of a control.
type Status string

const (
	StatusActive    Status = "active"
	StatusWithdrawn Status = "withdrawn"
)

// Reference represents an authoritative relationship to another canonical target.
type Reference struct {
	ID       string `json:"id"`
	Relation string `json:"relation"`
}

// Control represents a single normalized security control or enhancement.
type Control struct {
	ID         string      `json:"id"`
	Title      string      `json:"title"`
	Family     string      `json:"family"`
	ParentID   string      `json:"parent_id,omitempty"`
	Kind       Kind        `json:"kind"`
	Status     Status      `json:"status"`
	References []Reference `json:"references,omitempty"`
}

// Source describes the authoritative provenance and artifact fingerprint of the catalog.
type Source struct {
	Authority    string    `json:"authority"`               // e.g. "NIST"
	Standard     string    `json:"standard"`                // e.g. "SP 800-53"
	Revision     string    `json:"revision"`                // e.g. "5"
	Release      string    `json:"release"`                 // e.g. "5.2.0"
	ImportedFrom string    `json:"imported_from,omitempty"` // local consumed artifact path
	SHA256       string    `json:"sha256"`                  // 64-char hex artifact fingerprint
	ImportedAt   time.Time `json:"imported_at"`
}

// Catalog holds the entire collection of normalized controls and their source metadata.
type Catalog struct {
	Source   Source    `json:"source"`
	Controls []Control `json:"controls"`
}

// Verification represents the domain outcome of checking a control reference.
type Verification struct {
	ID            string      `json:"id"`                      // exact value supplied by the user
	Exists        bool        `json:"exists"`                  // true if the control exists (canonically or non-canonically)
	NonCanonical  bool        `json:"non_canonical,omitempty"` // true if ID exists but was cited non-canonically
	CanonicalID   string      `json:"canonical_id,omitempty"`  // official canonical ID if NonCanonical == true
	TitleChecked  bool        `json:"title_checked"`           // true if title was explicitly supplied and evaluated
	TitleMatches  bool        `json:"title_matches"`           // true if providedTitle == officialTitle
	ProvidedTitle string      `json:"provided_title,omitempty"`
	OfficialTitle string      `json:"official_title,omitempty"`
	Status        Status      `json:"status"`
	References    []Reference `json:"references,omitempty"`
}
