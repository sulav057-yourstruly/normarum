package control

import "strings"

// Verify checks whether a control reference exists and optionally verifies if the title matches.
// Mode 1: If title is empty, only existence is verified (TitleChecked is false).
// Mode 2: If title is non-empty, both existence and title equality are verified (TitleChecked is true).
func (c Catalog) Verify(id, title string) Verification {
	canonicalID := NormalizeLookupID(id)
	cleanTitle := strings.TrimSpace(title)

	ctrl, exists := c.Get(canonicalID)
	if !exists {
		return Verification{
			ID:            canonicalID,
			Exists:        false,
			TitleChecked:  cleanTitle != "",
			TitleMatches:  false,
			ProvidedTitle: cleanTitle,
		}
	}

	if cleanTitle == "" {
		return Verification{
			ID:            ctrl.ID,
			Exists:        true,
			TitleChecked:  false,
			TitleMatches:  false,
			OfficialTitle: ctrl.Title,
		}
	}

	matches := strings.EqualFold(cleanTitle, ctrl.Title)
	return Verification{
		ID:            ctrl.ID,
		Exists:        true,
		TitleChecked:  true,
		TitleMatches:  matches,
		ProvidedTitle: cleanTitle,
		OfficialTitle: ctrl.Title,
	}
}
