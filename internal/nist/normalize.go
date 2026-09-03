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
	strictSourceControlRegex = regexp.MustCompile(`^([a-z]{2,3})-([1-9]\d*)$`)
	// strictSourceEnhancementRegex matches official non-padded enhancements like "ac-6.2", "sc-7.10".
	strictSourceEnhancementRegex = regexp.MustCompile(`^([a-z]{2,3})-([1-9]\d*)\.([1-9]\d*)$`)
	// strictSourceFamilyRegex matches official group/family codes like "sr".
	strictSourceFamilyRegex = regexp.MustCompile(`^([a-z]{2,3})$`)
)

// normalizeSourceControlID strictly converts authoritative OSCAL control IDs into canonical form.
// Example:
//
//	"ac-6"   -> ("AC-6", nil)
//	"ac-6.2" -> ("AC-6(2)", nil)
//
// Malformed or unexpected forms (e.g. "ac-06", "ac6.2", "AC_06", "sr") return an error.
// Note: Family IDs (e.g. "sr") are NOT valid control IDs and will be rejected.
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

// normalizeSourceReferenceTarget normalizes an authoritative link target into canonical form.
// A reference target can be:
// - A control ID: "ac-6" -> "AC-6"
// - An enhancement ID: "ac-6.2" -> "AC-6(2)"
// - A statement fragment: "ac-2_smt.k" -> "AC-2"
// - A family group ID: "sr" -> "SR"
func normalizeSourceReferenceTarget(target string) (string, error) {
	clean := strings.TrimSpace(target)
	if clean == "" {
		return "", errors.New("source reference target is empty")
	}

	// If the reference points to a statement within a control (e.g. "ac-2_smt.k"),
	// resolve it to the enclosing control ID ("ac-2").
	if idx := strings.Index(clean, "_smt"); idx != -1 {
		clean = clean[:idx]
	}

	if m := strictSourceEnhancementRegex.FindStringSubmatch(clean); len(m) == 4 {
		family := strings.ToUpper(m[1])
		return fmt.Sprintf("%s-%s(%s)", family, m[2], m[3]), nil
	}

	if m := strictSourceControlRegex.FindStringSubmatch(clean); len(m) == 3 {
		family := strings.ToUpper(m[1])
		return fmt.Sprintf("%s-%s", family, m[2]), nil
	}

	if m := strictSourceFamilyRegex.FindStringSubmatch(clean); len(m) == 2 {
		return strings.ToUpper(m[1]), nil
	}

	return "", fmt.Errorf("malformed or unsupported reference target format: %q", target)
}

// controlStatus maps OSCAL properties to a canonical control.Status.
// If the status property is absent, it defaults to control.StatusActive.
// If status == "withdrawn", it returns control.StatusWithdrawn.
// Any other explicit status value returns an error.
func controlStatus(props []Property) (control.Status, error) {
	for _, p := range props {
		if strings.TrimSpace(p.Name) == "status" {
			val := strings.TrimSpace(p.Value)
			if val == "withdrawn" {
				return control.StatusWithdrawn, nil
			}
			return "", fmt.Errorf("unknown explicit control status: %q", val)
		}
	}
	return control.StatusActive, nil
}

// controlReferences extracts supported authoritative NIST relationships ("incorporated-into", "moved-to").
func controlReferences(links []Link) ([]control.Reference, error) {
	var refs []control.Reference
	for _, link := range links {
		rel := strings.TrimSpace(link.Rel)
		switch rel {
		case "incorporated-into", "moved-to":
			// Supported authoritative NIST relationships
		default:
			continue
		}

		href := strings.TrimSpace(link.Href)
		if !strings.HasPrefix(href, "#") {
			return nil, fmt.Errorf("malformed reference href %q: must start with '#'", href)
		}
		rawTarget := strings.TrimPrefix(href, "#")
		targetID, err := normalizeSourceReferenceTarget(rawTarget)
		if err != nil {
			return nil, fmt.Errorf("normalize reference target %q: %w", rawTarget, err)
		}

		refs = append(refs, control.Reference{
			ID:       targetID,
			Relation: rel,
		})
	}
	return refs, nil
}

var nistVersionRegex = regexp.MustCompile(`^5\.\d+\.\d+.*$`)

// validateDocumentIdentity performs a sanity check to verify that the parsed OSCAL document
// actually claims to represent NIST SP 800-53 Rev 5.
// Note: This is an identity sanity check; it does not cryptographically prove publisher authorship.
func validateDocumentIdentity(meta Metadata) error {
	title := strings.TrimSpace(meta.Title)
	hasRev5 := strings.Contains(title, "NIST SP 800-53 Rev 5") || strings.Contains(title, "NIST SP 800-53 Rev. 5")
	if !hasRev5 {
		return fmt.Errorf("unsupported catalog identity: metadata title %q does not identify as NIST SP 800-53 Rev 5", title)
	}

	version := strings.TrimSpace(meta.Version)
	if !nistVersionRegex.MatchString(version) {
		return fmt.Errorf("unsupported catalog identity: metadata version %q does not match expected 5.x format", version)
	}

	return nil
}

// Normalize constructs canonical standard data from a parsed NIST OSCAL document.
// Artifact provenance (SHA-256 fingerprint and source path) is attached by the
// source-loading boundary before the catalog becomes trusted through Validate().
func Normalize(doc Document) (control.Catalog, error) {
	if err := validateDocumentIdentity(doc.Catalog.Metadata); err != nil {
		return control.Catalog{}, err
	}

	if len(doc.Catalog.Groups) == 0 {
		return control.Catalog{}, errors.New("NIST OSCAL document contains no control groups")
	}

	release := strings.TrimSpace(doc.Catalog.Metadata.Version)
	source := control.Source{
		Authority:  "NIST",
		Standard:   "SP 800-53",
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

			status, err := controlStatus(oscalCtrl.Props)
			if err != nil {
				return control.Catalog{}, fmt.Errorf("control %q status: %w", oscalCtrl.ID, err)
			}

			refs, err := controlReferences(oscalCtrl.Links)
			if err != nil {
				return control.Catalog{}, fmt.Errorf("control %q references: %w", oscalCtrl.ID, err)
			}

			title := strings.TrimSpace(oscalCtrl.Title)
			controls = append(controls, control.Control{
				ID:         canonID,
				Title:      title,
				Family:     family,
				Kind:       control.KindControl,
				Status:     status,
				References: refs,
			})

			for _, oscalEnh := range oscalCtrl.Controls {
				enhCanonID, err := normalizeSourceControlID(oscalEnh.ID)
				if err != nil {
					return control.Catalog{}, fmt.Errorf("normalize enhancement %q: %w", oscalEnh.ID, err)
				}

				enhStatus, err := controlStatus(oscalEnh.Props)
				if err != nil {
					return control.Catalog{}, fmt.Errorf("enhancement %q status: %w", oscalEnh.ID, err)
				}

				enhRefs, err := controlReferences(oscalEnh.Links)
				if err != nil {
					return control.Catalog{}, fmt.Errorf("enhancement %q references: %w", oscalEnh.ID, err)
				}

				enhTitle := strings.TrimSpace(oscalEnh.Title)
				controls = append(controls, control.Control{
					ID:         enhCanonID,
					Title:      enhTitle,
					Family:     family,
					ParentID:   canonID,
					Kind:       control.KindEnhancement,
					Status:     enhStatus,
					References: enhRefs,
				})
			}
		}
	}

	if len(controls) == 0 {
		return control.Catalog{}, errors.New("NIST OSCAL document contains no controls")
	}

	cat := control.Catalog{
		Source:   source,
		Controls: controls,
	}

	// Ensure normalized catalog is deterministically ordered
	cat.Sort()

	return cat, nil
}
