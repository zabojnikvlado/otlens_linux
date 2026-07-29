package central

import (
	"context"
	"database/sql"
	"encoding/json"
)

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
func (r *Repository) BuildSegmentationConfigCommand(ctx context.Context, sensorID string) (string, error) {
	vlans, err := r.ListVLANConfig(ctx, sensorID)
	if err != nil {
		return "", err
	}
	maxLevelJump, err := r.GetMaxLevelJump(ctx, sensorID)
	if err != nil {
		return "", err
	}
	levels := make(map[uint16]float64, len(vlans))
	for _, v := range vlans {
		if v.PurdueLevel != nil {
			levels[uint16(v.VLANID)] = *v.PurdueLevel
		}
	}
	payload, err := json.Marshal(map[string]interface{}{
		"vlan_levels":    levels,
		"max_level_jump": maxLevelJump,
	})
	return string(payload), err
}

// VLANConfig is one VLAN's display name + assigned Purdue Model level
// — see vlan_config's doc comment in the embedded schema for the
// caveat about this not yet being what the sensor's own live
// segmentation_violation detection rule runs against.
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
		SELECT o.vlan_id, COALESCE(c.name,''), c.purdue_level,
               COUNT(DISTINCT COALESCE(NULLIF(o.mac,''), o.ip)) AS asset_count
		FROM topology_nodes o
		LEFT JOIN vlan_config c ON c.sensor_id = o.sensor_id AND c.vlan_id = o.vlan_id
		WHERE o.sensor_id = $1
          AND o.last_seen >= COALESCE((SELECT MAX(last_seen) FROM topology_nodes WHERE sensor_id=$1) - INTERVAL '5 minutes', NOW() - INTERVAL '5 minutes')
		GROUP BY o.vlan_id, c.name, c.purdue_level
		ORDER BY o.vlan_id ASC`,
		sensorID,
	)
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
			v.PurdueLevel = &level.Float64
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
	rows, err := r.db.QueryContext(ctx, `
		SELECT ip,mac,hostname,vendor,is_ot,protocols,confirmed,score,vlan_id,packet_count,first_seen,last_seen
		FROM topology_nodes WHERE sensor_id=$1 AND vlan_id=$2
          AND last_seen >= COALESCE((SELECT MAX(last_seen) FROM topology_nodes WHERE sensor_id=$1) - INTERVAL '5 minutes', NOW() - INTERVAL '5 minutes')
        ORDER BY ip`,
		sensorID, vlanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]topologyNodeRecord, 0)
	for rows.Next() {
		var n topologyNodeRecord
		var protocols string
		if err := rows.Scan(&n.IP, &n.MAC, &n.Hostname, &n.Vendor, &n.IsOT, &protocols, &n.Confirmed, &n.Score, &n.VLANID, &n.PacketCount, &n.FirstSeen, &n.LastSeen); err != nil {
			return nil, err
		}
		if protocols != "" {
			n.Protocols = protocols
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
