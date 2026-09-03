package nist80053

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ParseBaseline decodes an OSCAL JSON baseline profile from an io.Reader into a ProfileDocument,
// requiring that no unexpected data follows the JSON document.
func ParseBaseline(r io.Reader) (ProfileDocument, error) {
	if r == nil {
		return ProfileDocument{}, fmt.Errorf("decode NIST OSCAL baseline: reader is nil")
	}
	var doc ProfileDocument
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&doc); err != nil {
		return ProfileDocument{}, fmt.Errorf("decode NIST OSCAL baseline: %w", err)
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return ProfileDocument{}, errors.New("decode NIST OSCAL baseline: unexpected data after document")
		}
		return ProfileDocument{}, fmt.Errorf("decode NIST OSCAL baseline trailing data: %w", err)
	}

	return doc, nil
}

// ExtractBaselineControlIDs extracts and returns all control IDs included in the profile.
func (p *ProfileDocument) ExtractBaselineControlIDs() []string {
	var ids []string
	for _, imp := range p.Profile.Imports {
		for _, inc := range imp.IncludeControls {
			ids = append(ids, inc.WithIDs...)
		}
	}
	return ids
}
