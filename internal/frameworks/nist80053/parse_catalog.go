package nist80053

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Parse decodes an OSCAL JSON catalog from an io.Reader into a Document,
// requiring that no unexpected data follows the JSON document.
func Parse(r io.Reader) (Document, error) {
	if r == nil {
		return Document{}, fmt.Errorf("decode NIST OSCAL: reader is nil")
	}
	var doc Document
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&doc); err != nil {
		return Document{}, fmt.Errorf("decode NIST OSCAL: %w", err)
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Document{}, errors.New("decode NIST OSCAL: unexpected data after document")
		}
		return Document{}, fmt.Errorf("decode NIST OSCAL trailing data: %w", err)
	}

	return doc, nil
}
