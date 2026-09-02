package control

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	// userLookupEnhancementRegex matches input forms like "ac-6.2", "ac-6(2)", "AC-6 (2)", "AC-6.2".
	userLookupEnhancementRegex = regexp.MustCompile(`^([a-zA-Z]{2,3})[-_ ]*([0-9]+)[. (]+([0-9]+)\)?$`)
	// userLookupControlRegex matches input forms like "ac-6", "AC_6", "ac 6".
	userLookupControlRegex = regexp.MustCompile(`^([a-zA-Z]{2,3})[-_ ]*([0-9]+)$`)
)

// NormalizeLookupID performs convenient user-input normalization.
// For example:
//   "ac-6", "AC_6", "Ac-6" -> "AC-6"
//   "ac-6.2", "ac-6(2)", "AC-6(2)" -> "AC-6(2)"
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

// Validate verifies domain invariants on the normalized catalog.
func (c Catalog) Validate() error {
	if strings.TrimSpace(c.Source.Framework) == "" {
		return errors.New("catalog source framework is required")
	}
	if strings.TrimSpace(c.Source.Revision) == "" {
		return errors.New("catalog source revision is required")
	}
	if strings.TrimSpace(c.Source.Release) == "" {
		return errors.New("catalog source release is required")
	}

	idMap := make(map[string]Control, len(c.Controls))

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
		if _, exists := idMap[ctrl.ID]; exists {
			return fmt.Errorf("duplicate control ID %q", ctrl.ID)
		}
		idMap[ctrl.ID] = ctrl
	}

	// Second pass: validate parent-child hierarchy for enhancements
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

var keyRegex = regexp.MustCompile(`^([A-Z]+)-([0-9]+)(?:\(([0-9]+)\))?$`)

func parseControlIDKey(id string) (string, int, int) {
	m := keyRegex.FindStringSubmatch(id)
	if len(m) >= 3 {
		fam := m[1]
		num, _ := strconv.Atoi(m[2])
		enh := 0
		if len(m) == 4 && m[3] != "" {
			enh, _ = strconv.Atoi(m[3])
		}
		return fam, num, enh
	}
	return id, 0, 0
}

// Get finds a control by ID after normalizing the query ID.
func (c Catalog) Get(id string) (Control, bool) {
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
func (c Catalog) Search(query string) []Control {
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
