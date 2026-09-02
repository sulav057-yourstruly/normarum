package control

import "time"

// Kind distinguishes standard base controls from control enhancements.
type Kind string

const (
	KindControl     Kind = "control"
	KindEnhancement Kind = "enhancement"
)

// Control represents a single normalized security control or enhancement.
type Control struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Family   string `json:"family"`
	ParentID string `json:"parent_id,omitempty"`
	Kind     Kind   `json:"kind"`
}

// Source describes the authoritative provenance of the catalog.
type Source struct {
	Framework  string    `json:"framework"`
	Revision   string    `json:"revision"`
	Release    string    `json:"release"`
	ImportedAt time.Time `json:"imported_at"`
}

// Catalog holds the entire collection of normalized controls and their source metadata.
type Catalog struct {
	Source   Source    `json:"source"`
	Controls []Control `json:"controls"`
}

// Verification represents the domain outcome of checking a control reference.
type Verification struct {
	ID            string `json:"id"`
	Exists        bool   `json:"exists"`
	TitleChecked  bool   `json:"title_checked"`
	TitleMatches  bool   `json:"title_matches"`
	ProvidedTitle string `json:"provided_title,omitempty"`
	OfficialTitle string `json:"official_title,omitempty"`
}
