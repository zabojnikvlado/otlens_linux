package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Permissions is a role's grant set. View lists which tabs a user with
// this role sees in the Central UI (frontend nav filtering) — enforced
// again server-side by requireView, since hiding a nav button is not
// access control. Actions lists which mutating operations they're
// allowed to perform, independent of what they can see.
type Permissions struct {
	View    []string `json:"view"`
	Actions []string `json:"actions"`
}

func (p Permissions) HasView(tab string) bool {
	for _, v := range p.View {
		if v == tab {
			return true
		}
	}
	return false
}

func (p Permissions) HasAction(action string) bool {
	for _, a := range p.Actions {
		if a == action {
			return true
		}
	}
	return false
}

// allTabs/allActions are what the built-in "admin" role gets. Named
// slices rather than scattering the literal list across the file — a tab
// or action added later only needs to be added here to reach admin.
var allTabs = []string{"dashboard", "topology", "segmentation", "assets", "devices", "vulnerabilities", "tags", "rules", "alerts", "incidents", "sensors", "analysis", "users", "settings", "data", "audit", "reports"}
var allActions = []string{"sensor_start_stop", "asset_confirm_delete", "alert_confirm_approve", "rule_manage", "analysis_manage", "data_management", "users_roles_manage"}

// Role is one row of the roles table.
type Role struct {
	ID          string      `json:"ID"`
	Name        string      `json:"Name"`
	BuiltIn     bool        `json:"BuiltIn"`
	Permissions Permissions `json:"Permissions"`
	UpdatedAt   time.Time   `json:"UpdatedAt"`
}

// User is one row of the users table — never carries the password hash;
// that's handled separately (see SetUserPassword/authenticate) so a
// caller can't accidentally serialize it into an API response.
type User struct {
	ID                   string     `json:"ID"`
	Username             string     `json:"Username"`
	RoleID               string     `json:"RoleID"`
	DisplayName          string     `json:"DisplayName"`
	Enabled              bool       `json:"Enabled"`
	MustChangePassword   bool       `json:"MustChangePassword"`
	PasswordExpiresAt    *time.Time `json:"PasswordExpiresAt"`
	PasswordValidityDays *int       `json:"PasswordValidityDays"`
	CreatedAt            time.Time  `json:"CreatedAt"`
	LastLoginAt          *time.Time `json:"LastLoginAt"`
	Protected            bool       `json:"Protected"`
}

// sessionRow is what the auth middleware loads on every request — a join
// across sessions/users/roles in one query, since every authenticated
// request needs all three anyway.
type sessionRow struct {
	SessionID          string
	ExpiresAt          time.Time
	UserID             string
	Username           string
	Enabled            bool
	MustChangePassword bool
	PasswordExpiresAt  *time.Time
	RoleID             string
	Permissions        Permissions
}

const bootstrapAdminUserID = "user-bootstrap-admin"

var ErrNotFound = errors.New("not found")
var ErrBuiltInRole = errors.New("built-in roles cannot be deleted")
var ErrRoleInUse = errors.New("role is assigned to at least one user")
var ErrProtectedUser = errors.New("built-in administrator account cannot be deleted")
var ErrProtectedUserMutation = errors.New("built-in administrator must remain enabled with the Administrator role")

func isBuiltInRoleID(id string) bool {
	switch id {
	case "admin", "analyst", "view":
		return true
	default:
		return false
	}
}

// authBootstrapExecer is implemented by both *sql.DB and *sql.Tx. Keeping the
// bootstrap logic on this small interface lets a full Central reset restore and
// verify the authentication invariants inside the *same transaction* as the
// destructive reset. A reset can therefore never commit after deleting the
// built-in roles/administrator and only then fail while trying to recreate them.
type authBootstrapExecer interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

func builtInRoleDefaults() []Role {
	return []Role{
		{ID: "admin", Name: "Administrator", BuiltIn: true, Permissions: Permissions{View: allTabs, Actions: allActions}},
		{ID: "analyst", Name: "Analyst", BuiltIn: true, Permissions: Permissions{
			View:    []string{"dashboard", "topology", "segmentation", "assets", "devices", "vulnerabilities", "tags", "rules", "alerts", "incidents", "sensors", "analysis", "users", "reports"},
			Actions: []string{"asset_confirm_delete", "alert_confirm_approve", "rule_manage", "analysis_manage"},
		}},
		{ID: "view", Name: "View only", BuiltIn: true, Permissions: Permissions{
			View:    []string{"dashboard", "topology", "alerts", "incidents", "users", "reports"},
			Actions: []string{},
		}},
	}
}

func ensureAuthBootstrap(ctx context.Context, db authBootstrapExecer, bootstrapUsername, bootstrapPasswordHash string) error {
	for _, role := range builtInRoleDefaults() {
		perms, err := json.Marshal(role.Permissions)
		if err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx,
			`INSERT INTO roles(id,name,built_in,permissions) VALUES($1,$2,$3,$4)
			 ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,built_in=EXCLUDED.built_in,permissions=EXCLUDED.permissions,updated_at=NOW()`,
			role.ID, role.Name, role.BuiltIn, perms,
		); err != nil {
			return err
		}
	}

	// Prefer the fixed id used by current installations. If this database came
	// from an older OTLens version, the bootstrap administrator may already have
	// the configured username under a random id. In that case the username
	// conflict path upgrades the existing row in-place and marks it protected,
	// preserving its password and sessions instead of failing startup/reset.
	res, err := db.ExecContext(ctx,
		`UPDATE users SET role_id='admin', enabled=TRUE, protected=TRUE WHERE id=$1`,
		bootstrapAdminUserID,
	)
	if err != nil {
		return err
	}
	updated, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if updated == 0 {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO users(id,username,password_hash,role_id,display_name,enabled,protected,must_change_password)
			 VALUES($1,$2,$3,'admin',$4,TRUE,TRUE,TRUE)
			 ON CONFLICT(username) DO UPDATE SET role_id='admin',enabled=TRUE,protected=TRUE`,
			bootstrapAdminUserID, bootstrapUsername, bootstrapPasswordHash, "Administrator",
		); err != nil {
			return err
		}
	}

	// Fail closed if a future schema/reset change manages to violate one of the
	// invariants above. These checks run inside the reset transaction when
	// called from ResetCentral, so any destructive work is rolled back too.
	var builtInCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM roles WHERE id IN ('admin','analyst','view') AND built_in`).Scan(&builtInCount); err != nil {
		return err
	}
	if builtInCount != 3 {
		return fmt.Errorf("authentication bootstrap invariant failed: expected 3 built-in roles, got %d", builtInCount)
	}
	var protectedAdminCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE protected AND role_id='admin' AND enabled`).Scan(&protectedAdminCount); err != nil {
		return err
	}
	if protectedAdminCount < 1 {
		return errors.New("authentication bootstrap invariant failed: protected administrator missing")
	}
	return nil
}

// EnsureAuthBootstrap seeds/refreshes the three built-in roles on every
// startup — ON CONFLICT DO UPDATE, so if a role was seeded by an older
// version of this binary (missing a tab/action added since), it's
// brought back in sync with the current code's defaults automatically
// instead of silently staying stale forever. This only ever touches the
// three built-in ids; any custom role an admin created via the Roles tab
// is a completely separate row this loop never runs against, so it's
// never affected. (An admin's own edits *to a built-in role* also don't
// survive a restart under this scheme — built-ins are meant to track
// the code, custom roles are where real customization should live.)
// Also guarantees a protected built-in administrator account exists. Current
// installs use a fixed id; older databases are migrated in place by username.
// Existing administrator passwords are never reset by this bootstrap path.
func (r *Repository) EnsureAuthBootstrap(ctx context.Context, bootstrapUsername, bootstrapPasswordHash string) error {
	return ensureAuthBootstrap(ctx, r.db, bootstrapUsername, bootstrapPasswordHash)
}

func scanRole(row interface{ Scan(...interface{}) error }) (Role, error) {
	var role Role
	var perms []byte
	if err := row.Scan(&role.ID, &role.Name, &role.BuiltIn, &perms, &role.UpdatedAt); err != nil {
		return role, err
	}
	if err := json.Unmarshal(perms, &role.Permissions); err != nil {
		return role, err
	}
	return role, nil
}

func (r *Repository) ListRoles(ctx context.Context) ([]Role, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id,name,built_in,permissions,updated_at FROM roles ORDER BY built_in DESC, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Role, 0)
	for rows.Next() {
		role, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	return out, rows.Err()
}

func (r *Repository) GetRole(ctx context.Context, id string) (*Role, error) {
	role, err := scanRole(r.db.QueryRowContext(ctx, `SELECT id,name,built_in,permissions,updated_at FROM roles WHERE id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &role, nil
}

// UpsertRole creates a new custom role, or updates an existing role's
// name/permissions (built-in roles included — their permissions are
// editable via the Settings tab, only their id/existence is protected).
func (r *Repository) UpsertRole(ctx context.Context, id, name string, perms Permissions) error {
	data, err := json.Marshal(perms)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		`INSERT INTO roles(id,name,built_in,permissions) VALUES($1,$2,FALSE,$3)
		 ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,permissions=EXCLUDED.permissions,updated_at=NOW()`,
		id, name, data,
	)
	return err
}

func (r *Repository) DeleteRole(ctx context.Context, id string) error {
	// Protect the canonical IDs as well as the database flag. This keeps the
	// invariant intact even if an older database has a corrupted built_in flag.
	if isBuiltInRoleID(id) {
		return ErrBuiltInRole
	}
	role, err := r.GetRole(ctx, id)
	if err != nil {
		return err
	}
	if role.BuiltIn {
		return ErrBuiltInRole
	}
	var inUse int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role_id=$1`, id).Scan(&inUse); err != nil {
		return err
	}
	if inUse > 0 {
		return ErrRoleInUse
	}
	_, err = r.db.ExecContext(ctx, `DELETE FROM roles WHERE id=$1`, id)
	return err
}

func scanUser(row interface{ Scan(...interface{}) error }) (User, error) {
	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.RoleID, &u.DisplayName, &u.Enabled, &u.Protected, &u.MustChangePassword, &u.PasswordExpiresAt, &u.PasswordValidityDays, &u.CreatedAt, &u.LastLoginAt); err != nil {
		return u, err
	}
	return u, nil
}

func (r *Repository) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id,username,role_id,display_name,enabled,protected,must_change_password,password_expires_at,password_validity_days,created_at,last_login_at FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]User, 0)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (r *Repository) GetUser(ctx context.Context, id string) (*User, error) {
	u, err := scanUser(r.db.QueryRowContext(ctx, `SELECT id,username,role_id,display_name,enabled,protected,must_change_password,password_expires_at,password_validity_days,created_at,last_login_at FROM users WHERE id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// CreateUser inserts a brand-new account. passwordExpiresAt/validityDays
// are both nil for "never expires" — see the Users tab's "password
// validity" field. validityDays is remembered separately from the
// computed expires_at timestamp so any future password change (self-
// service or admin reset) can recompute a fresh expiry from the same
// policy instead of the clock silently stopping after the first change.
func (r *Repository) CreateUser(ctx context.Context, id, username, passwordHash, roleID, displayName string, mustChangePassword bool, passwordExpiresAt *time.Time, validityDays *int) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO users(id,username,password_hash,role_id,display_name,must_change_password,password_expires_at,password_validity_days)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		id, username, passwordHash, roleID, displayName, mustChangePassword, passwordExpiresAt, validityDays,
	)
	return err
}

// UpdateUser changes role/display name/enabled/password-validity-policy
// — never the password itself, see SetUserPassword for that. Changing
// validityDays here only affects the *next* password change's computed
// expiry, not the currently-set password_expires_at (that's updated
// explicitly by SetUserPassword when the password actually changes).
func (r *Repository) UpdateUser(ctx context.Context, id, roleID, displayName string, enabled bool, validityDays *int) error {
	var protected bool
	if err := r.db.QueryRowContext(ctx, `SELECT protected FROM users WHERE id=$1`, id).Scan(&protected); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if protected && (roleID != "admin" || !enabled) {
		return ErrProtectedUserMutation
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET role_id=$2,display_name=$3,enabled=$4,password_validity_days=$5 WHERE id=$1`,
		id, roleID, displayName, enabled, validityDays,
	)
	return err
}

func (r *Repository) DeleteUser(ctx context.Context, id string) error {
	var protected bool
	if err := r.db.QueryRowContext(ctx, `SELECT protected FROM users WHERE id=$1`, id).Scan(&protected); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if protected {
		return ErrProtectedUser
	}
	_, err := r.db.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, id)
	return err
}

// SetUserPassword is used by both self-service change-password and an
// admin's reset-password action. mustChangePassword should be false for
// a normal self-service change and true for an admin-issued temporary
// password (forces the recipient to set their own on next login).
// passwordExpiresAt should be computed by the caller from the account's
// current password_validity_days (nil stays "never expires").
func (r *Repository) SetUserPassword(ctx context.Context, id, passwordHash string, mustChangePassword bool, passwordExpiresAt *time.Time) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET password_hash=$2,must_change_password=$3,password_expires_at=$4 WHERE id=$1`,
		id, passwordHash, mustChangePassword, passwordExpiresAt,
	)
	return err
}

func (r *Repository) TouchLogin(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE users SET last_login_at=NOW() WHERE id=$1`, id)
	return err
}

// userAuthRow is the minimal data authenticateUser needs — username,
// password hash, and enough of the account's state to decide whether
// login should even be attempted.
type userAuthRow struct {
	ID           string
	PasswordHash string
	Enabled      bool
}

func (r *Repository) userAuthByUsername(ctx context.Context, username string) (*userAuthRow, error) {
	var u userAuthRow
	err := r.db.QueryRowContext(ctx, `SELECT id,password_hash,enabled FROM users WHERE username=$1`, username).Scan(&u.ID, &u.PasswordHash, &u.Enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *Repository) CreateSession(ctx context.Context, sessionID, userID string, expiresAt time.Time, userAgent, ip string) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO sessions(id,user_id,expires_at,user_agent,ip) VALUES($1,$2,$3,$4,$5)`,
		sessionID, userID, expiresAt, userAgent, ip,
	)
	return err
}

// GetSession loads a session together with its user and role in one
// query — every authenticated request needs all three, so this is the
// one query the auth middleware runs per request.
func (r *Repository) GetSession(ctx context.Context, sessionID string) (*sessionRow, error) {
	var s sessionRow
	var perms []byte
	err := r.db.QueryRowContext(ctx, `
		SELECT s.id, s.expires_at, u.id, u.username, u.enabled, u.must_change_password, u.password_expires_at, r.id, r.permissions
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		JOIN roles r ON r.id = u.role_id
		WHERE s.id = $1`, sessionID,
	).Scan(&s.SessionID, &s.ExpiresAt, &s.UserID, &s.Username, &s.Enabled, &s.MustChangePassword, &s.PasswordExpiresAt, &s.RoleID, &perms)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(perms, &s.Permissions); err != nil {
		return nil, err
	}
	return &s, nil
}

// TouchSession implements the sliding-expiry window: every authenticated
// request that finds a still-valid session pushes its expiry back out,
// so an active user is never logged out mid-session, but an idle one
// expires exactly session_duration after their last request.
func (r *Repository) TouchSession(ctx context.Context, sessionID string, expiresAt time.Time) error {
	_, err := r.db.ExecContext(ctx, `UPDATE sessions SET expires_at=$2, last_seen_at=NOW() WHERE id=$1`, sessionID, expiresAt)
	return err
}

func (r *Repository) DeleteSession(ctx context.Context, sessionID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE id=$1`, sessionID)
	return err
}

// DeleteSessionsForUser is used by resetPassword (an admin-issued
// temporary password invalidates every existing session for that
// account, so a session started under the old password can't keep
// running past the reset).
func (r *Repository) DeleteSessionsForUser(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=$1`, userID)
	return err
}
