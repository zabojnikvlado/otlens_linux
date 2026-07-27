package central

import (
	"context"
	"strings"
	"time"
)

// Device categories shown on the Devices tab.
const (
	CategoryOT      = "OT"
	CategoryIT      = "IT"
	CategoryMobile  = "Mobile"
	CategoryNetwork = "Network"
	CategoryRogue   = "Rogue/Unknown"
)

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
	_, err := r.db.ExecContext(ctx, `
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
		out[o.MAC] = o
	}
	return out, rows.Err()
}

// ImportAssetOverrides bulk-applies a parsed CSV (mac,category,name per
// row) — the Devices tab's "Import asset list" action. Returns how many
// rows were applied; malformed rows (empty MAC) are skipped, not fatal
// to the rest of the import.
func (r *Repository) ImportAssetOverrides(ctx context.Context, sensorID string, rows []AssetOverride, actor string) (int, error) {
	applied := 0
	now := time.Now()
	for _, row := range rows {
		mac := strings.TrimSpace(row.MAC)
		if mac == "" {
			continue
		}
		if _, err := r.db.ExecContext(ctx, `
			INSERT INTO asset_overrides(sensor_id, mac, category, name, updated_by, updated_at)
			VALUES($1,$2,$3,$4,$5,$6)
			ON CONFLICT(sensor_id, mac) DO UPDATE SET
				category = EXCLUDED.category, name = EXCLUDED.name,
				updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at`,
			sensorID, mac, strings.TrimSpace(row.Category), strings.TrimSpace(row.Name), actor, now,
		); err != nil {
			return applied, err
		}
		applied++
	}
	return applied, nil
}
