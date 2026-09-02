package nist

import (
	"errors"
	"fmt"
	"normarum/internal/control"
	"regexp"
	"strings"
	"time"
)

var (
	// strictSourceControlRegex matches official non-padded base controls like "ac-6", "pm-1".
	strictSourceControlRegex = regexp.MustCompile(`^([a-z]{2,3})-([1-9][0-9]*)$`)
	// strictSourceEnhancementRegex matches official non-padded enhancements like "ac-6.2", "sc-7.10".
	strictSourceEnhancementRegex = regexp.MustCompile(`^([a-z]{2,3})-([1-9][0-9]*)\.([1-9][0-9]*)$`)
)

// normalizeSourceControlID strictly converts authoritative OSCAL IDs into canonical form.
// Example:
//
//	"ac-6"   -> ("AC-6", nil)
//	"ac-6.2" -> ("AC-6(2)", nil)
//
// Malformed or unexpected forms (e.g. "ac-06", "ac6.2", "AC_06") return an error.
func normalizeSourceControlID(id string) (string, error) {
	clean := strings.TrimSpace(id)
	if clean == "" {
		return "", errors.New("source control ID is empty")
	}

	if m := strictSourceEnhancementRegex.FindStringSubmatch(clean); len(m) == 4 {
		family := strings.ToUpper(m[1])
		return fmt.Sprintf("%s-%s(%s)", family, m[2], m[3]), nil
	}

	if m := strictSourceControlRegex.FindStringSubmatch(clean); len(m) == 3 {
		family := strings.ToUpper(m[1])
		return fmt.Sprintf("%s-%s", family, m[2]), nil
	}

	return "", fmt.Errorf("malformed or unsupported source control ID format: %q", id)
}

// Normalize transforms an authoritative OSCAL Document into a framework-agnostic control.Catalog.
func Normalize(doc Document) (control.Catalog, error) {
	release := strings.TrimSpace(doc.Catalog.Metadata.Version)
	if release == "" {
		return control.Catalog{}, errors.New("NIST OSCAL metadata version is empty")
	}

	source := control.Source{
		Framework:  "NIST SP 800-53",
		Revision:   "5",
		Release:    release,
		ImportedAt: time.Now().UTC(),
	}

	var controls []control.Control

	for _, group := range doc.Catalog.Groups {
		family := strings.TrimSpace(group.Title)
		if family == "" {
			family = strings.ToUpper(strings.TrimSpace(group.ID))
		}

		for _, oscalCtrl := range group.Controls {
			canonID, err := normalizeSourceControlID(oscalCtrl.ID)
			if err != nil {
				return control.Catalog{}, fmt.Errorf("normalize control %q: %w", oscalCtrl.ID, err)
			}

			title := strings.TrimSpace(oscalCtrl.Title)
			controls = append(controls, control.Control{
				ID:     canonID,
				Title:  title,
				Family: family,
				Kind:   control.KindControl,
			})

			for _, oscalEnh := range oscalCtrl.Controls {
				enhCanonID, err := normalizeSourceControlID(oscalEnh.ID)
				if err != nil {
					return control.Catalog{}, fmt.Errorf("normalize enhancement %q: %w", oscalEnh.ID, err)
				}

				enhTitle := strings.TrimSpace(oscalEnh.Title)
				controls = append(controls, control.Control{
					ID:       enhCanonID,
					Title:    enhTitle,
					Family:   family,
					ParentID: canonID,
					Kind:     control.KindEnhancement,
				})
			}
		}
	}

	cat := control.Catalog{
		Source:   source,
		Controls: controls,
	}

	// Ensure normalized catalog is deterministically ordered
	cat.Sort()

	return cat, nil
}
