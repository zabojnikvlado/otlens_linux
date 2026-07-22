// Package vuln looks up known vulnerabilities for a device's vendor
// against a locally-loaded snapshot file — never a live network call.
// This is a deliberate design choice, not just a fallback: OT
// networks are routinely air-gapped from the internet on purpose
// (this is standard, expected practice, not an edge case to work
// around), so a feature that only works when the network happens to
// have internet access would be unusable in exactly the environment
// OTLens targets.
//
// The snapshot itself (a simple flat CSV — see LoadCSV) is prepared
// out of band, on a separate machine that does have internet access,
// from a public ICS-focused advisory feed (CISA ICS Advisories are
// the intended source — see DOCUMENTATION.md for where to get them
// and how to convert them into the CSV shape this package expects),
// and carried into the air-gapped network the same way other
// signature/definition updates already are in most OT environments
// (e.g. antivirus definitions) — manually, periodically, on removable
// media. Matching here is vendor-name only (see Advisory's doc
// comment for why that's a real precision limit, not a bug): OTLens
// has no way to fingerprint a device's exact product/firmware
// version passively, so this can only narrow to "known issues
// affecting this vendor," not "known issues affecting this specific
// device."
package vuln

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Advisory is one known vulnerability entry from the loaded
// snapshot. Matched against an asset by Vendor only — OTLens has no
// passive way to determine a device's exact product/firmware
// version, so Product is carried through for display only (to give
// a human reading the popup more context to judge relevance
// themselves), never used as a filter condition.
type Advisory struct {
	CVEID         string
	Vendor        string
	Product       string
	Severity      string
	Title         string
	PublishedDate string
	URL           string
}

// Database is the loaded, in-memory snapshot — safe for concurrent
// use. A zero-value Database (as returned by New when no path is
// configured) is a working no-op: Lookup always returns an empty
// slice rather than nil, so callers never need a separate
// "vulnerability lookup disabled" branch of their own.
type Database struct {
	mutex sync.RWMutex

	// byVendor is keyed by lowercased vendor name for
	// case-insensitive matching against oui.Lookup's output (which
	// isn't normalized to any particular case itself).
	byVendor map[string][]Advisory
}

// New builds an empty, working no-op Database. Use LoadCSV to
// actually populate it.
func New() *Database {
	return &Database{
		byVendor: make(map[string][]Advisory),
	}
}

// LoadCSV (re)loads the snapshot from path, replacing whatever was
// previously loaded, and returns how many advisory rows were
// accepted (for a startup log line). Expected columns, in order, no
// header row:
//
//	cve_id,vendor,product,severity,title,published_date,url
//
// See DOCUMENTATION.md for exactly how to produce this file from
// CISA's public ICS Advisories feed. Malformed rows (wrong column
// count) are skipped rather than failing the whole load — a
// hand-curated or converted snapshot is more likely to have a few
// rough edges than to be uniformly broken, and one bad row shouldn't
// cost every other row in the file.
func (db *Database) LoadCSV(path string) (int, error) {

	f, err := os.Open(path)

	if err != nil {
		return 0, fmt.Errorf("opening vulnerability snapshot %q failed: %w", path, err)
	}

	defer f.Close()

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()

	if err != nil {
		return 0, fmt.Errorf("parsing vulnerability snapshot %q failed: %w", path, err)
	}

	byVendor := make(map[string][]Advisory)
	loadedCount := 0

	for _, row := range records {

		if len(row) < 7 {
			continue
		}

		advisory := Advisory{
			CVEID:         strings.TrimSpace(row[0]),
			Vendor:        strings.TrimSpace(row[1]),
			Product:       strings.TrimSpace(row[2]),
			Severity:      strings.TrimSpace(row[3]),
			Title:         strings.TrimSpace(row[4]),
			PublishedDate: strings.TrimSpace(row[5]),
			URL:           strings.TrimSpace(row[6]),
		}

		if advisory.CVEID == "" || advisory.Vendor == "" {
			continue
		}

		key := strings.ToLower(advisory.Vendor)
		byVendor[key] = append(byVendor[key], advisory)
		loadedCount++
	}

	db.mutex.Lock()
	db.byVendor = byVendor
	db.mutex.Unlock()

	return loadedCount, nil
}

// Lookup returns every advisory whose vendor matches (case-
// insensitive, exact match on the vendor name as loaded — not a
// substring search, since e.g. "Siemens" matching against a snapshot
// row for "Siemens AG" would need normalization work the snapshot
// preparation step is responsible for, not this lookup). Always
// returns a non-nil slice (empty if nothing matches, vendor is
// "Unknown vendor", or nothing was ever loaded), so callers can
// range over the result unconditionally.
func (db *Database) Lookup(vendor string) []Advisory {

	db.mutex.RLock()
	defer db.mutex.RUnlock()

	result := db.byVendor[strings.ToLower(strings.TrimSpace(vendor))]

	if result == nil {
		return []Advisory{}
	}

	// Return a copy of the slice header pointing at the same
	// backing array is fine here — Advisory is never mutated after
	// load, only replaced wholesale on the next LoadCSV.
	out := make([]Advisory, len(result))
	copy(out, result)

	return out
}

// Count returns how many advisories are currently loaded, across all
// vendors — used for a startup log line and nothing else.
func (db *Database) Count() int {

	db.mutex.RLock()
	defer db.mutex.RUnlock()

	total := 0

	for _, advisories := range db.byVendor {
		total += len(advisories)
	}

	return total
}
