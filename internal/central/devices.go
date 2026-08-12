package central

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Coarse categories emitted by automatic classification. Manual inventory
// overrides support the richer category vocabulary exposed by the Devices UI.
const (
	CategoryOT      = "OT"
	CategoryIT      = "IT"
	CategoryMobile  = "Mobile"
	CategoryNetwork = "Network"
	CategoryRogue   = "Rogue/Unknown"
)

var assetCategories = []string{
	"IT", "OT", "Workstation", "Server", "Engineering Workstation",
	"HMI/SCADA", "PLC/RTU", "Historian", "Network", "Security Appliance",
	"Virtualization", "Storage/NAS", "Printer", "Mobile", "IoT",
	"Rogue/Unknown",
}

// AssetCategory is one operator-selectable device category. Built-in
// categories seed every Central installation and cannot be deleted; operators
// can add/remove custom categories through the Device classification tab.
type AssetCategory struct {
	Name      string    `json:"name"`
	BuiltIn   bool      `json:"built_in"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
}

var (
	ErrBuiltInAssetCategory = errors.New("built-in asset category cannot be deleted")
	ErrInvalidAssetCategory = errors.New("invalid asset category")
	ErrAssetCategoryExists  = errors.New("asset category already exists")
)

func validateAssetCategoryName(category string) (string, error) {
	category = strings.TrimSpace(category)
	if category == "" {
		return "", fmt.Errorf("%w: category is required", ErrInvalidAssetCategory)
	}
	if !utf8.ValidString(category) {
		return "", fmt.Errorf("%w: category must be valid UTF-8", ErrInvalidAssetCategory)
	}
	if utf8.RuneCountInString(category) > 64 {
		return "", fmt.Errorf("%w: category must be at most 64 characters", ErrInvalidAssetCategory)
	}
	if strings.IndexFunc(category, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("%w: category must not contain control characters", ErrInvalidAssetCategory)
	}
	return category, nil
}

// mobileVendorHints/networkVendorHints are substring matches against
// the OUI-resolved vendor name — best-effort only. A vendor making both
// phones and network gear (Apple, Samsung, Huawei) will sometimes guess
// wrong; that's exactly what asset_overrides exists to correct, either
// one device at a time from the Devices tab or in bulk via CSV import.
// This is deliberately not authoritative.
var mobileVendorHints = []string{
	"apple", "samsung electr", "xiaomi", "huawei device", "oneplus",
	"google inc", "motorola mobility", "oppo", "vivo mobile",
}

func normalizeAssetMAC(mac string) (string, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil || len(hw) != 6 {
		return "", fmt.Errorf("invalid 48-bit MAC address %q", mac)
	}
	return strings.ToLower(hw.String()), nil
}

func normalizeAssetCategory(category string) (string, bool) {
	category = strings.TrimSpace(category)
	for _, allowed := range assetCategories {
		if strings.EqualFold(category, allowed) {
			return allowed, true
		}
	}
	return "", false
}

func validAssetCategory(category string) bool {
	_, ok := normalizeAssetCategory(category)
	return ok
}

// NormalizeAssetCategory resolves an operator supplied name to the canonical
// spelling stored in the category catalogue. Matching is case-insensitive so
// CSV imports remain friendly while the value persisted on the asset remains
// stable and display-ready.
func (r *Repository) NormalizeAssetCategory(ctx context.Context, category string) (string, bool, error) {
	category = strings.TrimSpace(category)
	if category == "" {
		return "", false, nil
	}
	var canonical string
	err := r.db.QueryRowContext(ctx, `SELECT name FROM asset_categories WHERE lower(name)=lower($1) LIMIT 1`, category).Scan(&canonical)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return canonical, true, nil
}

func (r *Repository) ListAssetCategories(ctx context.Context) ([]AssetCategory, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT name,built_in,created_by,created_at
		FROM asset_categories
		ORDER BY built_in DESC, lower(name), name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AssetCategory, 0)
	for rows.Next() {
		var category AssetCategory
		if err := rows.Scan(&category.Name, &category.BuiltIn, &category.CreatedBy, &category.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, category)
	}
	return out, rows.Err()
}

func (r *Repository) AddAssetCategory(ctx context.Context, name, actor string) (AssetCategory, error) {
	name, err := validateAssetCategoryName(name)
	if err != nil {
		return AssetCategory{}, err
	}
	var category AssetCategory
	err = r.db.QueryRowContext(ctx, `
		INSERT INTO asset_categories(name,built_in,created_by,created_at)
		VALUES($1,FALSE,$2,NOW())
		ON CONFLICT DO NOTHING
		RETURNING name,built_in,created_by,created_at`, name, actor,
	).Scan(&category.Name, &category.BuiltIn, &category.CreatedBy, &category.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AssetCategory{}, fmt.Errorf("%w: %q", ErrAssetCategoryExists, name)
	}
	return category, err
}

// DeleteAssetCategory removes a custom category and safely clears that
// category override from any assigned devices. Their optional friendly name is
// preserved, and classification falls back to the automatic IT/OT/vendor
// logic until an operator assigns another category.
func (r *Repository) DeleteAssetCategory(ctx context.Context, name, actor string) (int64, error) {
	name = strings.TrimSpace(name)
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var canonical string
	var builtIn bool
	err = tx.QueryRowContext(ctx, `SELECT name,built_in FROM asset_categories WHERE lower(name)=lower($1) LIMIT 1 FOR UPDATE`, name).Scan(&canonical, &builtIn)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	if builtIn {
		return 0, ErrBuiltInAssetCategory
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE asset_overrides
		SET category='', updated_by=$2, updated_at=NOW()
		WHERE lower(category)=lower($1)`, canonical, actor)
	if err != nil {
		return 0, err
	}
	cleared, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM asset_categories WHERE name=$1`, canonical); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return cleared, nil
}

var networkVendorHints = []string{
	"cisco", "juniper", "netgear", "ubiquiti", "mikrotik", "arista",
	"tp-link", "d-link", "aruba", "fortinet", "palo alto", "hewlett packard enterprise",
	"extreme networks", "ruckus", "zyxel", "netscreen", "check point",
}

// classifyDeviceCategory is the automatic fallback used when no
// asset_overrides row exists for a device — see ListDevices. isOT
// takes priority (it's derived from actually observing an OT protocol,
// far more reliable than a vendor-name guess); an unconfirmed asset is
// Rogue/Unknown regardless of vendor, since "is this expected on the
// network at all" is a more urgent question than "what kind of thing
// is it."
func classifyDeviceCategory(vendor string, isOT, confirmed bool) string {
	if isOT {
		return CategoryOT
	}
	if !confirmed {
		return CategoryRogue
	}
	v := strings.ToLower(vendor)
	for _, hint := range networkVendorHints {
		if strings.Contains(v, hint) {
			return CategoryNetwork
		}
	}
	for _, hint := range mobileVendorHints {
		if strings.Contains(v, hint) {
			return CategoryMobile
		}
	}
	return CategoryIT
}

// AssetOverride is one manually-set or imported category/name — see
// asset_overrides' doc comment in the embedded schema.
type AssetOverride struct {
	MAC      string
	Category string
	Name     string
}

// SetAssetCategory records a manual category (and optionally a
// friendlier name) for one device, overriding the automatic guess —
// used by both the single-device "set category" action and, row by
// row, by ImportAssetOverrides.
func (r *Repository) SetAssetCategory(ctx context.Context, sensorID, mac, category, name, actor string) error {
	var err error
	mac, err = normalizeAssetMAC(mac)
	if err != nil {
		return err
	}
	requestedCategory := strings.TrimSpace(category)
	category, ok, err := r.NormalizeAssetCategory(ctx, requestedCategory)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w %q", ErrInvalidAssetCategory, requestedCategory)
	}
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO asset_overrides(sensor_id, mac, category, name, updated_by, updated_at)
		VALUES($1,$2,$3,$4,$5,NOW())
		ON CONFLICT(sensor_id, mac) DO UPDATE SET
			category = EXCLUDED.category, name = EXCLUDED.name,
			updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
		sensorID, mac, category, name, actor,
	)
	return err
}

// ListAssetOverrides returns every override for a sensor, keyed by MAC
// — used to merge into the automatic classification when building the
// Devices tab response.
func (r *Repository) ListAssetOverrides(ctx context.Context, sensorID string) (map[string]AssetOverride, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT mac, category, name FROM asset_overrides WHERE sensor_id=$1`, sensorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]AssetOverride)
	for rows.Next() {
		var o AssetOverride
		if err := rows.Scan(&o.MAC, &o.Category, &o.Name); err != nil {
			return nil, err
		}
		if normalized, err := normalizeAssetMAC(o.MAC); err == nil {
			o.MAC = normalized
			out[normalized] = o
		}
	}
	return out, rows.Err()
}

// ImportAssetOverrides bulk-applies a parsed CSV (mac,category,name per
// row) — the Devices tab's "Import asset list" action. Returns how many
// rows were applied; malformed rows (empty MAC) are skipped, not fatal
// to the rest of the import.
func (r *Repository) ImportAssetOverrides(ctx context.Context, sensorID string, rows []AssetOverride, actor string) (int, error) {
	// Treat a bulk inventory import as one operator action. A database error in
	// the middle must not leave a half-applied asset list that the UI reports as
	// failed and the analyst then retries against an unknown partial state.
	categoryRows, err := r.db.QueryContext(ctx, `SELECT name FROM asset_categories`)
	if err != nil {
		return 0, err
	}
	categories := make(map[string]string)
	for categoryRows.Next() {
		var name string
		if err := categoryRows.Scan(&name); err != nil {
			categoryRows.Close()
			return 0, err
		}
		categories[strings.ToLower(name)] = name
	}
	if err := categoryRows.Err(); err != nil {
		categoryRows.Close()
		return 0, err
	}
	categoryRows.Close()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	applied := 0
	now := time.Now()
	for _, row := range rows {
		mac, err := normalizeAssetMAC(row.MAC)
		if err != nil {
			continue
		}
		category, ok := categories[strings.ToLower(strings.TrimSpace(row.Category))]
		if !ok {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO asset_overrides(sensor_id, mac, category, name, updated_by, updated_at)
			VALUES($1,$2,$3,$4,$5,$6)
			ON CONFLICT(sensor_id, mac) DO UPDATE SET
				category = EXCLUDED.category, name = EXCLUDED.name,
				updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at`,
			sensorID, mac, category, strings.TrimSpace(row.Name), actor, now,
		); err != nil {
			return 0, err
		}
		applied++
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return applied, nil
}
