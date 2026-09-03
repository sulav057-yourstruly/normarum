package nist80053

// Document represents the top-level OSCAL document structure.
type Document struct {
	Catalog Catalog `json:"catalog"`
}

// Catalog represents the OSCAL catalog object.
type Catalog struct {
	Metadata Metadata `json:"metadata"`
	Groups   []Group  `json:"groups"`
}

// Metadata holds source catalog metadata.
type Metadata struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

// Group represents an OSCAL group, typically representing a control family.
type Group struct {
	ID       string    `json:"id"`
	Title    string    `json:"title"`
	Controls []Control `json:"controls"`
}

// Property represents an OSCAL property.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Link represents an OSCAL relationship link.
type Link struct {
	Href string `json:"href"`
	Rel  string `json:"rel"`
}

// Control represents an OSCAL control or nested control enhancement.
type Control struct {
	ID       string     `json:"id"`
	Title    string     `json:"title"`
	Props    []Property `json:"props,omitempty"`
	Links    []Link     `json:"links,omitempty"`
	Controls []Control  `json:"controls,omitempty"`
}

// ProfileDocument represents the top-level OSCAL profile document structure.
type ProfileDocument struct {
	Profile Profile `json:"profile"`
}

// Profile represents the OSCAL profile object.
type Profile struct {
	Metadata Metadata        `json:"metadata"`
	Imports  []ProfileImport `json:"imports"`
}

// ProfileImport represents an import element in an OSCAL profile.
type ProfileImport struct {
	Href            string            `json:"href"`
	IncludeControls []IncludeControls `json:"include-controls"`
}

// IncludeControls represents controls selected for inclusion in a profile.
type IncludeControls struct {
	WithIDs []string `json:"with-ids"`
}
