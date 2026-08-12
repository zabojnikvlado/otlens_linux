package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"

	"github.com/zabojnikvlado/otlens_linux/internal/management"
)

func validVLANID(vlanID int) bool { return vlanID >= 0 && vlanID <= 4094 }

func validPurdueLevel(level float64) bool {
	for _, allowed := range []float64{0, 1, 2, 3, 3.5, 4, 5} {
		if math.Abs(level-allowed) < 0.001 {
			return true
		}
	}
	return false
}

func validatePurdueLevel(level *float64) error {
	if level != nil && !validPurdueLevel(*level) {
		return fmt.Errorf("invalid Purdue level %.3g; allowed levels are 0, 1, 2, 3, 3.5, 4, 5", *level)
	}
	return nil
}

// GetMaxLevelJump returns a sensor's configured max_level_jump (see
// segmentation_settings' doc comment in the embedded schema), or 1
// (the sensor's own local-config default) if nothing's been set yet.
func (r *Repository) GetMaxLevelJump(ctx context.Context, sensorID string) (float64, error) {
	var jump float64
	err := r.db.QueryRowContext(ctx, `SELECT max_level_jump FROM segmentation_settings WHERE sensor_id=$1`, sensorID).Scan(&jump)
	if err == sql.ErrNoRows {
		return 1, nil
	}
	if err != nil {
		return 0, err
	}
	return jump, nil
}

// SetMaxLevelJump sets a sensor's max_level_jump — the Network
// Segmentation tab's per-sensor setting.
func (r *Repository) SetMaxLevelJump(ctx context.Context, sensorID string, maxLevelJump float64, actor string) error {
	if maxLevelJump <= 0 || maxLevelJump > 5 {
		return fmt.Errorf("max_level_jump must be > 0 and <= 5")
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO segmentation_settings(sensor_id, max_level_jump, updated_by, updated_at)
		VALUES($1,$2,$3,NOW())
		ON CONFLICT(sensor_id) DO UPDATE SET
			max_level_jump = EXCLUDED.max_level_jump, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
		sensorID, maxLevelJump, actor,
	)
	return err
}

// BuildSegmentationConfigCommand assembles the "segmentation.config"
// command payload for a sensor: every VLAN with an assigned Purdue
// level (from vlan_config) plus max_level_jump (from
// segmentation_settings) — the full picture the sensor's live
// segmentation_violation detection rule needs, in the one shape
// detect.Engine.UpdateSegmentationConfig expects. Called by
// setVLANConfig and setMaxLevelJump after either changes, so the
// sensor always has an up-to-date copy without an admin needing to
// also edit that sensor's local config.yaml — see
// DOCUMENTATION.md's Network Segmentation section.
func (r *Repository) HasSegmentationConfig(ctx context.Context, sensorID string) (bool, error) {
	var yes bool
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM vlan_config WHERE sensor_id=$1) OR EXISTS(SELECT 1 FROM segmentation_settings WHERE sensor_id=$1)`, sensorID).Scan(&yes)
	return yes, err
}

func (r *Repository) SegmentationConfig(ctx context.Context, sensorID string) (management.SegmentationConfig, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT vlan_id,purdue_level FROM vlan_config WHERE sensor_id=$1 AND purdue_level IS NOT NULL`, sensorID)
	if err != nil {
		return management.SegmentationConfig{}, err
	}
	defer rows.Close()
	levels := map[uint16]float64{}
	for rows.Next() {
		var id int
		var level float64
		if err := rows.Scan(&id, &level); err != nil {
			return management.SegmentationConfig{}, err
		}
		// Ignore legacy-corrupt rows rather than wrapping them into uint16. New
		// writes are strictly validated below.
		if !validVLANID(id) || !validPurdueLevel(level) {
			continue
		}
		levels[uint16(id)] = level
	}
	if err := rows.Err(); err != nil {
		return management.SegmentationConfig{}, err
	}
	jump, err := r.GetMaxLevelJump(ctx, sensorID)
	if err != nil {
		return management.SegmentationConfig{}, err
	}
	if jump <= 0 || jump > 5 {
		jump = 1
	}
	return management.SegmentationConfig{Managed: true, VLANLevels: levels, MaxLevelJump: jump}, nil
}

func (r *Repository) BuildSegmentationConfigCommand(ctx context.Context, sensorID string) (string, error) {
	config, err := r.SegmentationConfig(ctx, sensorID)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(config)
	return string(payload), err
}

// VLANConfig is one VLAN's display name + assigned Purdue Model level
// Central is authoritative once a sensor has any Central-side segmentation
// configuration; the same snapshot is pushed immediately and on every sync.
type VLANConfig struct {
	VLANID      int
	Name        string
	PurdueLevel *float64
	AssetCount  int
}

// ListVLANConfig returns every VLAN currently observed for a sensor
// (from topology_nodes, so it includes VLANs that have never been
// explicitly named/leveled), left-joined with whatever vlan_config
// naming/level exists — so the Network Segmentation tab can show every
// real VLAN, not just the ones someone's already configured.
func (r *Repository) ListVLANConfig(ctx context.Context, sensorID string) ([]VLANConfig, error) {
	rows, err := r.db.QueryContext(ctx, `
        WITH current_nodes AS (
          SELECT * FROM (
            SELECT n.*, ROW_NUMBER() OVER (
              PARTITION BY CASE WHEN mac<>'' THEN 'mac:'||lower(mac) ELSE 'ip:'||ip END
              ORDER BY last_seen DESC, ip ASC
            ) rn
            FROM topology_nodes n WHERE sensor_id=$1 AND active=TRUE
          ) x WHERE rn=1
        ), observed AS (
          SELECT vlan_id, COUNT(*)::int asset_count FROM current_nodes GROUP BY vlan_id
        )
        SELECT COALESCE(o.vlan_id,c.vlan_id), COALESCE(c.name,''), c.purdue_level, COALESCE(o.asset_count,0)
        FROM observed o FULL OUTER JOIN vlan_config c ON c.sensor_id=$1 AND c.vlan_id=o.vlan_id
        WHERE c.sensor_id=$1 OR o.vlan_id IS NOT NULL
        ORDER BY 1`, sensorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]VLANConfig, 0)
	for rows.Next() {
		var v VLANConfig
		var level sql.NullFloat64
		if err := rows.Scan(&v.VLANID, &v.Name, &level, &v.AssetCount); err != nil {
			return nil, err
		}
		if level.Valid {
			x := level.Float64
			v.PurdueLevel = &x
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// SetVLANConfig names a VLAN and/or assigns it a Purdue Model level —
// the Network Segmentation tab's per-VLAN edit action. purdueLevel nil
// clears the level (marks the VLAN unclassified again) rather than
// leaving it at whatever it was.
func (r *Repository) SetVLANConfig(ctx context.Context, sensorID string, vlanID int, name string, purdueLevel *float64, actor string) error {
	if !validVLANID(vlanID) {
		return fmt.Errorf("vlan_id must be between 0 and 4094")
	}
	if err := validatePurdueLevel(purdueLevel); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO vlan_config(sensor_id, vlan_id, name, purdue_level, updated_by, updated_at)
		VALUES($1,$2,$3,$4,$5,NOW())
		ON CONFLICT(sensor_id, vlan_id) DO UPDATE SET
			name = EXCLUDED.name, purdue_level = EXCLUDED.purdue_level,
			updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
		sensorID, vlanID, name, purdueLevel, actor,
	)
	return err
}

// ListVLANAssets returns every asset currently on a given VLAN for a
// sensor — the Network Segmentation tab's "which assets are in this
// segment" drill-down.
func (r *Repository) ListVLANAssets(ctx context.Context, sensorID string, vlanID int) ([]topologyNodeRecord, error) {
	if !validVLANID(vlanID) {
		return nil, fmt.Errorf("vlan_id must be between 0 and 4094")
	}
	rows, err := r.db.QueryContext(ctx, `
        SELECT ip,mac,hostname,vendor,is_ot,protocols,confirmed,score,vlan_id,packet_count,first_seen,last_seen
        FROM (
          SELECT n.*, ROW_NUMBER() OVER (
            PARTITION BY CASE WHEN mac<>'' THEN 'mac:'||lower(mac) ELSE 'ip:'||ip END
            ORDER BY last_seen DESC, ip ASC
          ) rn
          FROM topology_nodes n WHERE sensor_id=$1 AND active=TRUE
        ) current_nodes
        WHERE rn=1 AND vlan_id=$2
        ORDER BY ip`, sensorID, vlanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]topologyNodeRecord, 0)
	for rows.Next() {
		var n topologyNodeRecord
		if err := rows.Scan(&n.IP, &n.MAC, &n.Hostname, &n.Vendor, &n.IsOT, &n.Protocols, &n.Confirmed, &n.Score, &n.VLANID, &n.PacketCount, &n.FirstSeen, &n.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
