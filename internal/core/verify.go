package core

// Verify checks whether an exact control reference exists, whether it is active, and optionally verifies if the title matches exactly.
// If title is nil, title verification is omitted (TitleChecked is false).
// If title is non-nil (even if empty string ""), title verification is performed against the exact official title (TitleChecked is true).
// Note: Verification never silently corrects, trims, or case-folds input.
func (c *Catalog) Verify(id string, title *string) Verification {
	// Step 1: Check for exact canonical match.
	ctrl, exact := c.getExact(id)
	if !exact {
		// Step 2: Check if forgiving discovery would have matched.
		if match, found := c.Get(id); found {
			// The control exists, but the user cited a non-canonical identifier.
			// Halt immediately before evaluating status or title.
			return Verification{
				ID:            id,
				Exists:        true,
				NonCanonical:  true,
				CanonicalID:   match.ID,
				TitleChecked:  false,
				TitleMatches:  false,
				OfficialTitle: match.Title,
				Status:        match.Status,
			}
		}

		// Control does not exist at all.
		var providedTitle string
		if title != nil {
			providedTitle = *title
		}
		return Verification{
			ID:            id,
			Exists:        false,
			TitleChecked:  title != nil,
			TitleMatches:  false,
			ProvidedTitle: providedTitle,
		}
	}

	// Step 3: Exact match succeeded.
	res := Verification{
		ID:            id,
		Exists:        true,
		NonCanonical:  false,
		Status:        ctrl.Status,
		OfficialTitle: ctrl.Title,
		References:    ctrl.References,
	}

	// Step 4: Withdrawn check.
	// Withdrawn controls exist historically, but always fail reference verification.
	// Halt before evaluating title to match the decision tree precedence.
	if ctrl.Status == StatusWithdrawn {
		res.TitleChecked = false
		res.TitleMatches = false
		return res
	}

	// Step 5: Active control - title evaluation.
	if title == nil {
		res.TitleChecked = false
		res.TitleMatches = false
		return res
	}

	res.TitleChecked = true
	res.ProvidedTitle = *title
	res.TitleMatches = (*title == ctrl.Title)
	return res
}
