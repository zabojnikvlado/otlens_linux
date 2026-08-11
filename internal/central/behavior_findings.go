package central

import (
	"encoding/json"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zabojnikvlado/otlens_linux/internal/management"
)

type AssetBehaviorProfile struct {
	SensorID       string    `json:"sensor_id"`
	AssetIP        string    `json:"asset_ip"`
	HealthScore    float64   `json:"health_score"`
	AnomalyScore   float64   `json:"anomaly_score"`
	Confidence     float64   `json:"confidence"`
	State          string    `json:"state"`
	ActiveFindings int       `json:"active_findings"`
	TopReason      string    `json:"top_reason,omitempty"`
	LastEvaluated  time.Time `json:"last_evaluated,omitempty"`
}

type NetworkBehaviorOverview struct {
	NetworkHealth    float64                `json:"network_health"`
	State            string                 `json:"state"`
	LearningComplete bool                   `json:"learning_complete"`
	Coverage         float64                `json:"coverage"`
	ActiveBaselines  uint64                 `json:"active_baselines"`
	BehaviorAlerts   int                    `json:"behavior_alerts"`
	AffectedAssets   int                    `json:"affected_assets"`
	TopAnomaly       *AssetBehaviorProfile  `json:"top_anomaly,omitempty"`
	Profiles         []AssetBehaviorProfile `json:"profiles"`
}

func behaviorReadAccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		p := identityFromContext(c).Permissions
		if !p.HasView(ViewDashboard) && !p.HasView(ViewAssets) && !p.HasView(ViewAlerts) && !p.HasView(ViewTopology) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}

func behaviorNumber(evidence map[string]interface{}, key string) float64 {
	value, _ := evidence[key].(float64)
	return value
}

func behaviorReason(evidence map[string]interface{}) string {
	values, ok := evidence["reasons"].([]interface{})
	if !ok || len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(strings.TrimSpace(strings.Join(strings.Fields(toString(values[0])), " ")))
}

func toString(value interface{}) string {
	if text, ok := value.(string); ok {
		return text
	}
	data, _ := json.Marshal(value)
	return string(data)
}

func buildBehaviorOverview(alerts []AlertHistoryEntry, telemetry []management.TelemetrySnapshot, assetCount int) NetworkBehaviorOverview {
	type baselineStatus struct {
		Behavior struct {
			Enabled       bool   `json:"enabled"`
			Mode          string `json:"mode"`
			Profiles      uint64 `json:"profiles"`
			AssetProfiles uint64 `json:"asset_profiles"`
		} `json:"behavior"`
	}
	overview := NetworkBehaviorOverview{LearningComplete: true, State: "unknown", Profiles: []AssetBehaviorProfile{}}
	var covered uint64
	for _, snapshot := range telemetry {
		var status baselineStatus
		if json.Unmarshal(snapshot.Baseline, &status) != nil || !status.Behavior.Enabled {
			overview.LearningComplete = false
			continue
		}
		overview.ActiveBaselines += status.Behavior.Profiles
		covered += status.Behavior.AssetProfiles
		if status.Behavior.Mode != "monitoring" {
			overview.LearningComplete = false
		}
	}
	if len(telemetry) == 0 {
		overview.LearningComplete = false
	}
	if assetCount > 0 {
		overview.Coverage = math.Min(100, float64(covered)*100/float64(assetCount))
	}

	byAsset := make(map[string]*AssetBehaviorProfile)
	for _, alert := range alerts {
		if !strings.HasPrefix(alert.Type, "behavior_") || !alert.Active {
			continue
		}
		key := alert.SensorID + "\x00" + alert.IP
		profile := byAsset[key]
		if profile == nil {
			profile = &AssetBehaviorProfile{SensorID: alert.SensorID, AssetIP: alert.IP, State: "healthy"}
			byAsset[key] = profile
		}
		score := math.Max(0, math.Min(100, behaviorNumber(alert.Evidence, "risk_score")))
		confidence := math.Max(0, math.Min(1, behaviorNumber(alert.Evidence, "confidence")))
		profile.ActiveFindings++
		overview.BehaviorAlerts++
		if score >= profile.AnomalyScore {
			profile.AnomalyScore = score
			profile.Confidence = confidence
			profile.TopReason = behaviorReason(alert.Evidence)
		}
		if alert.LastSeen.After(profile.LastEvaluated) {
			profile.LastEvaluated = alert.LastSeen
		}
	}
	var weightedScore, weightTotal float64
	for _, profile := range byAsset {
		profile.HealthScore = 100 - profile.AnomalyScore
		switch {
		case profile.AnomalyScore >= 70:
			profile.State = "critical"
		case profile.AnomalyScore >= 40:
			profile.State = "anomalous"
		default:
			profile.State = "healthy"
		}
		weight := math.Max(.25, profile.Confidence)
		weightedScore += profile.AnomalyScore * weight
		weightTotal += weight
		overview.Profiles = append(overview.Profiles, *profile)
	}
	sort.Slice(overview.Profiles, func(i, j int) bool { return overview.Profiles[i].AnomalyScore > overview.Profiles[j].AnomalyScore })
	overview.AffectedAssets = len(overview.Profiles)
	if len(overview.Profiles) > 0 {
		top := overview.Profiles[0]
		overview.TopAnomaly = &top
		overview.NetworkHealth = 100 - weightedScore/weightTotal
	} else if overview.LearningComplete && overview.Coverage > 0 {
		overview.NetworkHealth = 100
	}
	switch {
	case !overview.LearningComplete || overview.Coverage == 0:
		overview.State = "learning"
	case overview.NetworkHealth < 60:
		overview.State = "critical"
	case overview.NetworkHealth < 85:
		overview.State = "degraded"
	default:
		overview.State = "healthy"
	}
	return overview
}

func (s *Server) behaviorOverview(c *gin.Context) {
	alerts, err := s.Repo.ListAlertHistory(c.Request.Context(), 2000)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	telemetry, err := s.Repo.Telemetry(c.Request.Context())
	if err != nil {
		respondInternalError(c, err)
		return
	}
	assetCount := 0
	for _, snapshot := range telemetry {
		var graph struct {
			Nodes []json.RawMessage `json:"Nodes"`
		}
		if json.Unmarshal(snapshot.Topology, &graph) == nil {
			assetCount += len(graph.Nodes)
		}
	}
	c.JSON(http.StatusOK, buildBehaviorOverview(alerts, telemetry, assetCount))
}

func (s *Server) behaviorFindings(c *gin.Context) {
	alerts, err := s.Repo.ListAlertHistory(c.Request.Context(), 2000)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	result := make([]AlertHistoryEntry, 0)
	for _, alert := range alerts {
		if strings.HasPrefix(alert.Type, "behavior_") {
			result = append(result, alert)
		}
	}
	c.JSON(http.StatusOK, result)
}

func (s *Server) behaviorFinding(c *gin.Context) {
	id := c.Param("id")
	alerts, err := s.Repo.ListAlertHistory(c.Request.Context(), 2000)
	if err != nil {
		respondInternalError(c, err)
		return
	}
	for _, alert := range alerts {
		if alert.AlertKey == id && strings.HasPrefix(alert.Type, "behavior_") {
			c.JSON(http.StatusOK, alert)
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "behavior finding not found"})
}
