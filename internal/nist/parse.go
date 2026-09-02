package nist

import (
	"encoding/json"
	"fmt"
	"io"
)

// Parse decodes an OSCAL JSON catalog from an io.Reader into a Document.
func Parse(r io.Reader) (Document, error) {
	if r == nil {
		return Document{}, fmt.Errorf("decode NIST OSCAL: reader is nil")
	}
	var doc Document
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&doc); err != nil {
		return Document{}, fmt.Errorf("decode NIST OSCAL: %w", err)
	}
	return doc, nil
}
