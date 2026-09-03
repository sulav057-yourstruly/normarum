package control

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	// userLookupEnhancementRegex matches input forms like "ac-6.2", "ac-6(2)", "AC-6 (2)", "AC-6.2".
	userLookupEnhancementRegex = regexp.MustCompile(`^([a-zA-Z]{2,3})[-_ ]*(\d+)[. (]+(\d+)\)?$`)
	// userLookupControlRegex matches input forms like "ac-6", "AC_6", "ac 6".
	userLookupControlRegex = regexp.MustCompile(`^([a-zA-Z]{2,3})[-_ ]*(\d+)$`)
)

// NormalizeLookupID performs convenient user-input normalization.
// For example:
//
//	"ac-6", "AC_6", "Ac-6" -> "AC-6"
//	"ac-6.2", "ac-6(2)", "AC-6(2)" -> "AC-6(2)"
func NormalizeLookupID(id string) string {
	clean := strings.TrimSpace(id)
	if clean == "" {
		return ""
	}

	if m := userLookupEnhancementRegex.FindStringSubmatch(clean); len(m) == 4 {
		family := strings.ToUpper(m[1])
		controlNum, _ := strconv.Atoi(m[2])
		enhancementNum, _ := strconv.Atoi(m[3])
		return fmt.Sprintf("%s-%d(%d)", family, controlNum, enhancementNum)
	}

	if m := userLookupControlRegex.FindStringSubmatch(clean); len(m) == 3 {
		family := strings.ToUpper(m[1])
		controlNum, _ := strconv.Atoi(m[2])
		return fmt.Sprintf("%s-%d", family, controlNum)
	}

	return strings.ToUpper(clean)
}

// Validate confirms that the catalog satisfies Normarum's trust invariants.
func (c *Catalog) Validate() error {
	if strings.TrimSpace(c.Source.Authority) == "" {
		return errors.New("catalog source authority is required")
	}
	if strings.TrimSpace(c.Source.Standard) == "" {
		return errors.New("catalog source standard is required")
	}
	if strings.TrimSpace(c.Source.Revision) == "" {
		return errors.New("catalog source revision is required")
	}
	if strings.TrimSpace(c.Source.Release) == "" {
		return errors.New("catalog source release is required")
	}

	decodedSHA, err := hex.DecodeString(c.Source.SHA256)
	if err != nil || len(decodedSHA) != sha256.Size {
		return errors.New("invalid source SHA-256: must be a valid 64-character hexadecimal hash")
	}

	if len(c.Controls) == 0 {
		return errors.New("catalog must contain at least one control")
	}

	idMap := make(map[string]Control, len(c.Controls))
	familyMap := make(map[string]struct{})

	// First pass: validate each control's fields and uniqueness
	for _, ctrl := range c.Controls {
		if strings.TrimSpace(ctrl.ID) == "" {
			return errors.New("control ID cannot be empty")
		}
		if strings.TrimSpace(ctrl.Title) == "" {
			return fmt.Errorf("control %q has empty title", ctrl.ID)
		}
		if ctrl.Kind != KindControl && ctrl.Kind != KindEnhancement {
			return fmt.Errorf("control %q has invalid kind %q", ctrl.ID, ctrl.Kind)
		}
		if ctrl.Status != StatusActive && ctrl.Status != StatusWithdrawn {
			return fmt.Errorf("control %q has invalid status %q", ctrl.ID, ctrl.Status)
		}
		if _, exists := idMap[ctrl.ID]; exists {
			return fmt.Errorf("duplicate control ID %q", ctrl.ID)
		}
		idMap[ctrl.ID] = ctrl

		fam, _, _ := parseControlIDKey(ctrl.ID)
		if fam != "" {
			familyMap[fam] = struct{}{}
		}
	}

	// Second pass: validate parent-child hierarchy for enhancements and reference integrity
	for _, ctrl := range c.Controls {
		if ctrl.Kind == KindEnhancement {
			if strings.TrimSpace(ctrl.ParentID) == "" {
				return fmt.Errorf("enhancement %q is missing parent ID", ctrl.ID)
			}
			if ctrl.ParentID == ctrl.ID {
				return fmt.Errorf("enhancement %q cannot be its own parent", ctrl.ID)
			}
			parent, exists := idMap[ctrl.ParentID]
			if !exists {
				return fmt.Errorf("enhancement %q references non-existent parent %q", ctrl.ID, ctrl.ParentID)
			}
			if parent.Kind != KindControl {
				return fmt.Errorf("enhancement %q parent %q must be a control, got %q", ctrl.ID, ctrl.ParentID, parent.Kind)
			}
		}

		if len(ctrl.References) > 0 {
			seenRefs := make(map[string]struct{}, len(ctrl.References))
			for _, ref := range ctrl.References {
				targetID := strings.TrimSpace(ref.ID)
				if targetID == "" {
					return fmt.Errorf("control %q has reference with empty target ID", ctrl.ID)
				}
				relation := strings.TrimSpace(ref.Relation)
				if relation == "" {
					return fmt.Errorf("control %q reference %q has empty relation", ctrl.ID, targetID)
				}
				if targetID == ctrl.ID {
					return fmt.Errorf("control %q cannot reference itself", ctrl.ID)
				}
				_, inIDMap := idMap[targetID]
				_, inFamilyMap := familyMap[targetID]
				if !inIDMap && !inFamilyMap {
					return fmt.Errorf("control %q references non-existent target %q", ctrl.ID, targetID)
				}
				refKey := relation + "\x00" + targetID
				if _, dup := seenRefs[refKey]; dup {
					return fmt.Errorf("control %q has duplicate reference (%s, %s)", ctrl.ID, relation, targetID)
				}
				seenRefs[refKey] = struct{}{}
			}
		}
	}

	return nil
}

// Sort sorts the catalog's controls in place in canonical natural order.
func (c *Catalog) Sort() {
	sort.Slice(c.Controls, func(i, j int) bool {
		return compareControlIDs(c.Controls[i].ID, c.Controls[j].ID)
	})
}

// compareControlIDs provides natural hierarchical sorting: AC-1 < AC-2 < AC-6 < AC-6(1) < AC-6(2) < AC-10 < IA-1.
func compareControlIDs(a, b string) bool {
	famA, numA, enhA := parseControlIDKey(a)
	famB, numB, enhB := parseControlIDKey(b)

	if famA != famB {
		return famA < famB
	}
	if numA != numB {
		return numA < numB
	}
	return enhA < enhB
}

var keyRegex = regexp.MustCompile(`^([A-Z]+)-(\d+)(?:\((\d+)\))?$`)

func parseControlIDKey(id string) (fam string, num, enh int) {
	m := keyRegex.FindStringSubmatch(id)
	if len(m) >= 3 {
		fam = m[1]
		num, _ = strconv.Atoi(m[2])
		enh = 0
		if len(m) == 4 && m[3] != "" {
			enh, _ = strconv.Atoi(m[3])
		}
		return fam, num, enh
	}
	return id, 0, 0
}

// getExact finds a control by exact, unnormalized, case-sensitive ID.
func (c *Catalog) getExact(id string) (Control, bool) {
	for _, ctrl := range c.Controls {
		if ctrl.ID == id {
			return ctrl, true
		}
	}
	return Control{}, false
}

// Get finds a control by ID after normalizing the query ID (forgiving discovery).
func (c *Catalog) Get(id string) (Control, bool) {
	canonicalID := NormalizeLookupID(id)
	if canonicalID == "" {
		return Control{}, false
	}
	for _, ctrl := range c.Controls {
		if ctrl.ID == canonicalID {
			return ctrl, true
		}
	}
	return Control{}, false
}

// Search finds all controls whose ID or Title contains the query (case-insensitively).
func (c *Catalog) Search(query string) []Control {
	q := strings.TrimSpace(strings.ToLower(query))
	if q == "" {
		return nil
	}

	var matches []Control
	for _, ctrl := range c.Controls {
		if strings.Contains(strings.ToLower(ctrl.ID), q) || strings.Contains(strings.ToLower(ctrl.Title), q) {
			matches = append(matches, ctrl)
		}
	}
	return matches
}
