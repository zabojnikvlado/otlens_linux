package central

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

const sessionCookieName = "otlens_session"

// View tab keys — must match the frontend's data-tab attributes exactly.
const (
	ViewDashboard = "dashboard"
	ViewTopology  = "topology"
	ViewAssets    = "assets"
	ViewTags      = "tags"
	ViewRules     = "rules"
	ViewAlerts    = "alerts"
	ViewSensors   = "sensors"
	ViewAnalysis  = "analysis"
	ViewSettings  = "settings"
	ViewData      = "data"
)

// Action keys — independent of view; a role could in principle see a tab
// without any action grant in it (e.g. "view" role sees Alerts but can't
// confirm/approve anything there).
const (
	ActionSensorStartStop    = "sensor_start_stop"
	ActionAssetConfirmDelete = "asset_confirm_delete"
	ActionAlertConfirmApprove = "alert_confirm_approve"
	ActionRuleManage         = "rule_manage"
	ActionAnalysisManage     = "analysis_manage"
	ActionDataManagement     = "data_management"
	ActionUsersRolesManage   = "users_roles_manage"
)

// tokenAuthPermissions is what the legacy management_token bearer-auth
// fallback grants — full access, since it's an unattributed break-glass
// credential rather than a specific person's account. See the config
// comment on auth.management_token.
var tokenAuthPermissions = Permissions{View: allTabs, Actions: allActions}

// changePasswordAllowedPaths are reachable even while a session's
// must_change_password flag is set — everything else 403s until the
// account has a real password. Kept as full request paths (including the
// /v1 prefix) since that's what gin gives us in authMiddleware, before
// routing has resolved which handler will run.
var changePasswordAllowedPaths = map[string]bool{
	"/v1/me":              true,
	"/v1/logout":          true,
	"/v1/change-password": true,
}

func hashPassword(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	return string(b), err
}

// HashPassword is exported for cmd/otlens-central/main.go's one-time
// bootstrap-admin creation — everywhere else in this package uses the
// unexported hashPassword directly.
func HashPassword(plain string) (string, error) { return hashPassword(plain) }

func checkPassword(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// newRandomToken returns a hex-encoded, cryptographically random
// identifier — used for both session IDs and admin-issued temporary
// passwords. 32 bytes (256 bits) for session IDs is deliberately
// generous; it's the only thing standing in for "this browser is
// authenticated" so it needs to be unguessable, not just unique.
func newRandomToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// requestIdentity is what authMiddleware attaches to the gin context for
// every downstream handler — via c.Set("identity", ...).
type requestIdentity struct {
	Authenticated      bool
	ViaToken           bool // true for the management_token fallback path
	UserID             string
	Username           string
	Permissions        Permissions
	MustChangePassword bool
}

func identityFromContext(c *gin.Context) requestIdentity {
	v, ok := c.Get("identity")
	if !ok {
		return requestIdentity{}
	}
	id, ok := v.(requestIdentity)
	if !ok {
		return requestIdentity{}
	}
	return id
}

// authMiddleware replaces the old single-shared-token bearerAuth for the
// management API. It tries the session cookie first (the normal path for
// the Central UI); if that's absent or invalid, it falls back to the
// legacy Authorization: Bearer management_token (kept only as an
// emergency/break-glass path — see auth.management_token in the config).
// Neither present/valid -> 401.
func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if cookie, err := c.Cookie(sessionCookieName); err == nil && cookie != "" {
			session, err := s.Repo.GetSession(c, cookie)
			if err == nil {
				if !session.Enabled {
					s.clearSessionCookie(c)
					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "account disabled"})
					return
				}
				if session.ExpiresAt.Before(time.Now()) {
					_ = s.Repo.DeleteSession(c, cookie)
					s.clearSessionCookie(c)
				} else {
					// Sliding expiry: an active session's clock resets on
					// every request, so it only ever expires after
					// SessionDuration of no activity, never mid-use.
					newExpiry := time.Now().Add(s.SessionDuration)
					_ = s.Repo.TouchSession(c, cookie, newExpiry)
					s.setSessionCookie(c, cookie, newExpiry)

					identity := requestIdentity{
						Authenticated:      true,
						UserID:             session.UserID,
						Username:           session.Username,
						Permissions:        session.Permissions,
						MustChangePassword: session.MustChangePassword || isPasswordExpired(session.PasswordExpiresAt),
					}
					c.Set("identity", identity)
					if identity.MustChangePassword && !changePasswordAllowedPaths[c.Request.URL.Path] {
						c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "password_change_required"})
						return
					}
					c.Next()
					return
				}
			}
		}

		// Fall back to the emergency management token.
		if s.ManagementToken != "" {
			auth := c.GetHeader("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				got := strings.TrimPrefix(auth, "Bearer ")
				if got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.ManagementToken)) == 1 {
					c.Set("identity", requestIdentity{Authenticated: true, ViaToken: true, Permissions: tokenAuthPermissions})
					c.Next()
					return
				}
			}
		}

		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
	}
}

func isPasswordExpired(expiresAt *time.Time) bool {
	return expiresAt != nil && expiresAt.Before(time.Now())
}

func (s *Server) setSessionCookie(c *gin.Context, value string, expiresAt time.Time) {
	c.SetSameSite(http.SameSiteStrictMode)
	maxAge := int(time.Until(expiresAt).Seconds())
	c.SetCookie(sessionCookieName, value, maxAge, "/", "", s.WebTLSEnabled, true)
}

func (s *Server) clearSessionCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(sessionCookieName, "", -1, "/", "", s.WebTLSEnabled, true)
}

// requireView aborts with 403 unless the caller's role includes this tab
// in its View grant. Hiding a nav button client-side is a UX nicety, not
// access control — every route needs this too.
func requireView(tab string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !identityFromContext(c).Permissions.HasView(tab) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}

func requireAction(action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !identityFromContext(c).Permissions.HasAction(action) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}

// --- Public (unauthenticated) endpoints ---

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) login(c *gin.Context) {
	var req loginRequest
	if c.ShouldBindJSON(&req) != nil || strings.TrimSpace(req.Username) == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username and password are required"})
		return
	}
	auth, err := s.Repo.userAuthByUsername(c, req.Username)
	if err != nil || !checkPassword(auth.PasswordHash, req.Password) {
		// Deliberately identical error for "no such user" and "wrong
		// password" — distinguishing them lets an attacker enumerate
		// valid usernames.
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
		return
	}
	if !auth.Enabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "account disabled"})
		return
	}
	sessionID, err := newRandomToken(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session creation failed"})
		return
	}
	expiresAt := time.Now().Add(s.SessionDuration)
	if err := s.Repo.CreateSession(c, sessionID, auth.ID, expiresAt, c.Request.UserAgent(), c.ClientIP()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	_ = s.Repo.TouchLogin(c, auth.ID)
	s.setSessionCookie(c, sessionID, expiresAt)

	user, role, err := s.loadUserAndRole(c, auth.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"User":               user,
		"Role":               role,
		"Permissions":        role.Permissions,
		"MustChangePassword": user.MustChangePassword || isPasswordExpired(user.PasswordExpiresAt),
	})
}

func (s *Server) logout(c *gin.Context) {
	if cookie, err := c.Cookie(sessionCookieName); err == nil && cookie != "" {
		_ = s.Repo.DeleteSession(c, cookie)
	}
	s.clearSessionCookie(c)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// --- Authenticated-but-not-permission-gated endpoints ---

func (s *Server) me(c *gin.Context) {
	identity := identityFromContext(c)
	if identity.ViaToken {
		c.JSON(http.StatusOK, gin.H{
			"ViaToken":           true,
			"Username":           "management-token",
			"Permissions":        identity.Permissions,
			"MustChangePassword": false,
		})
		return
	}
	user, role, err := s.loadUserAndRole(c, identity.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"User":               user,
		"Role":               role,
		"Permissions":        role.Permissions,
		"MustChangePassword": user.MustChangePassword || isPasswordExpired(user.PasswordExpiresAt),
	})
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) changePassword(c *gin.Context) {
	identity := identityFromContext(c)
	if identity.ViaToken || identity.UserID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "not available for the management token"})
		return
	}
	var req changePasswordRequest
	if c.ShouldBindJSON(&req) != nil || len(req.NewPassword) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "new password must be at least 8 characters"})
		return
	}
	auth, err := s.Repo.userAuthByUsername(c, identity.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// A forced change (must_change_password/expired) doesn't require
	// knowing the old temporary/expired password's *purpose* to be
	// re-entered here — it still has to be the correct current password,
	// same as any other change. This just isn't a "forgot password"
	// flow; that's the admin-mediated reset below.
	if !checkPassword(auth.PasswordHash, req.CurrentPassword) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "current password is incorrect"})
		return
	}
	user, err := s.Repo.GetUser(c, identity.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	hash, err := hashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	expiresAt := computeExpiry(user.PasswordValidityDays)
	if err := s.Repo.SetUserPassword(c, identity.UserID, hash, false, expiresAt); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func computeExpiry(validityDays *int) *time.Time {
	if validityDays == nil || *validityDays <= 0 {
		return nil
	}
	t := time.Now().AddDate(0, 0, *validityDays)
	return &t
}

func (s *Server) loadUserAndRole(ctx context.Context, userID string) (*User, *Role, error) {
	user, err := s.Repo.GetUser(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	role, err := s.Repo.GetRole(ctx, user.RoleID)
	if err != nil {
		return nil, nil, err
	}
	return user, role, nil
}

// --- Admin-only: users & roles management (requireAction(ActionUsersRolesManage)) ---

func (s *Server) listUsers(c *gin.Context) {
	users, err := s.Repo.ListUsers(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, users)
}

type createUserRequest struct {
	Username             string `json:"username"`
	Password             string `json:"password"`
	RoleID               string `json:"role_id"`
	DisplayName          string `json:"display_name"`
	PasswordValidityDays *int   `json:"password_validity_days"`
	MustChangePassword   bool   `json:"must_change_password"`
}

func (s *Server) createUser(c *gin.Context) {
	var req createUserRequest
	if c.ShouldBindJSON(&req) != nil || strings.TrimSpace(req.Username) == "" || len(req.Password) < 8 || req.RoleID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username, role_id, and a password of at least 8 characters are required"})
		return
	}
	if _, err := s.Repo.GetRole(c, req.RoleID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown role_id"})
		return
	}
	hash, err := hashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	id, err := newRandomToken(8)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	expiresAt := computeExpiry(req.PasswordValidityDays)
	if err := s.Repo.CreateUser(c, "user-"+id, req.Username, hash, req.RoleID, req.DisplayName, req.MustChangePassword, expiresAt, req.PasswordValidityDays); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"ok": true})
}

type updateUserRequest struct {
	RoleID               string `json:"role_id"`
	DisplayName          string `json:"display_name"`
	Enabled              bool   `json:"enabled"`
	PasswordValidityDays *int   `json:"password_validity_days"`
}

func (s *Server) updateUser(c *gin.Context) {
	id := c.Param("id")
	var req updateUserRequest
	if c.ShouldBindJSON(&req) != nil || req.RoleID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role_id is required"})
		return
	}
	if _, err := s.Repo.GetRole(c, req.RoleID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown role_id"})
		return
	}
	if err := s.Repo.UpdateUser(c, id, req.RoleID, req.DisplayName, req.Enabled, req.PasswordValidityDays); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !req.Enabled {
		// Disabling an account kills any session it's currently using —
		// otherwise a disabled user stays logged in until their session
		// naturally expires.
		_ = s.Repo.DeleteSessionsForUser(c, id)
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) deleteUser(c *gin.Context) {
	id := c.Param("id")
	if id == identityFromContext(c).UserID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot delete your own account while logged in as it"})
		return
	}
	_ = s.Repo.DeleteSessionsForUser(c, id)
	if err := s.Repo.DeleteUser(c, id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// resetUserPassword is the admin-mediated password reset: there's no
// email/SMS infrastructure to assume in an OT environment that's often
// air-gapped, so instead of a self-service "forgot password" link, an
// admin generates a random temporary password here, reads it out to the
// user through whatever out-of-band channel they'd use anyway (in
// person, phone, ticketing system), and it's shown here exactly once —
// it is never stored or retrievable in cleartext again. must_change_password
// is forced, so the temporary password only works to log in and
// immediately set a real one; every existing session for the account is
// also killed, so a session opened under the old password doesn't keep
// running past the reset.
func (s *Server) resetUserPassword(c *gin.Context) {
	id := c.Param("id")
	user, err := s.Repo.GetUser(c, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	temp, err := newRandomToken(9) // 18 hex chars — short enough to read aloud, long enough to not matter that it's shown once
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	hash, err := hashPassword(temp)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	expiresAt := computeExpiry(user.PasswordValidityDays)
	if err := s.Repo.SetUserPassword(c, id, hash, true, expiresAt); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	_ = s.Repo.DeleteSessionsForUser(c, id)
	c.JSON(http.StatusOK, gin.H{"TemporaryPassword": temp})
}

func (s *Server) listRoles(c *gin.Context) {
	roles, err := s.Repo.ListRoles(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, roles)
}

type upsertRoleRequest struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Permissions Permissions `json:"permissions"`
}

func (s *Server) upsertRole(c *gin.Context) {
	var req upsertRoleRequest
	if c.ShouldBindJSON(&req) != nil || strings.TrimSpace(req.ID) == "" || strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id and name are required"})
		return
	}
	if err := s.Repo.UpsertRole(c, req.ID, req.Name, req.Permissions); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) deleteRole(c *gin.Context) {
	id := c.Param("id")
	if err := s.Repo.DeleteRole(c, id); err != nil {
		switch {
		case errors.Is(err, ErrBuiltInRole):
			c.JSON(http.StatusBadRequest, gin.H{"error": "built-in roles cannot be deleted"})
		case errors.Is(err, ErrRoleInUse):
			c.JSON(http.StatusConflict, gin.H{"error": "role is still assigned to at least one user"})
		case errors.Is(err, ErrNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
