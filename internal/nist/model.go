package nist

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
