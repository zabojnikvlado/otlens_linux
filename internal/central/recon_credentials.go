package central

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zabojnikvlado/otlens_linux/internal/management"
)

func credentialKey() ([]byte, error) {
	v := strings.TrimSpace(os.Getenv("OTLENS_CREDENTIAL_MASTER_KEY"))
	if len(v) < 16 {
		return nil, errors.New("OTLENS_CREDENTIAL_MASTER_KEY must contain at least 16 characters")
	}
	h := sha256.Sum256([]byte(v))
	return h[:], nil
}
func encryptCredential(v management.ReconCredentialSecret) ([]byte, error) {
	k, e := credentialKey()
	if e != nil {
		return nil, e
	}
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	block, e := aes.NewCipher(k)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, g.NonceSize())
	if _, e = io.ReadFull(rand.Reader, nonce); e != nil {
		return nil, e
	}
	return g.Seal(nonce, nonce, b, nil), nil
}
func decryptCredential(b []byte) (management.ReconCredentialSecret, error) {
	var v management.ReconCredentialSecret
	k, e := credentialKey()
	if e != nil {
		return v, e
	}
	block, e := aes.NewCipher(k)
	if e != nil {
		return v, e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return v, e
	}
	if len(b) < g.NonceSize() {
		return v, errors.New("invalid encrypted credential")
	}
	nonce, c := b[:g.NonceSize()], b[g.NonceSize():]
	plain, e := g.Open(nil, nonce, c, nil)
	if e != nil {
		return v, e
	}
	e = json.Unmarshal(plain, &v)
	return v, e
}
func credentialID() string { return "cred-" + strings.TrimPrefix(reconID(), "recon-") }

func (r *Repository) ListReconCredentials(ctx context.Context) ([]management.ReconCredential, error) {
	rows, e := r.db.QueryContext(ctx, `SELECT id,name,type,username,created_at,updated_at FROM reconnaissance_credentials ORDER BY name`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []management.ReconCredential
	for rows.Next() {
		var x management.ReconCredential
		if e = rows.Scan(&x.ID, &x.Name, &x.Type, &x.Username, &x.CreatedAt, &x.UpdatedAt); e != nil {
			return nil, e
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
func (r *Repository) SaveReconCredential(ctx context.Context, x management.ReconCredentialSecret) error {
	enc, e := encryptCredential(x)
	if e != nil {
		return e
	}
	_, e = r.db.ExecContext(ctx, `INSERT INTO reconnaissance_credentials(id,name,type,username,encrypted_secret) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,type=EXCLUDED.type,username=EXCLUDED.username,encrypted_secret=EXCLUDED.encrypted_secret,updated_at=NOW()`, x.ID, x.Name, x.Type, x.Username, enc)
	return e
}
func (r *Repository) GetReconCredential(ctx context.Context, id string) (management.ReconCredentialSecret, error) {
	var b []byte
	e := r.db.QueryRowContext(ctx, `SELECT encrypted_secret FROM reconnaissance_credentials WHERE id=$1`, id).Scan(&b)
	if e != nil {
		return management.ReconCredentialSecret{}, e
	}
	return decryptCredential(b)
}
func (r *Repository) DeleteReconCredential(ctx context.Context, id string) error {
	_, e := r.db.ExecContext(ctx, `DELETE FROM reconnaissance_credentials WHERE id=$1`, id)
	return e
}

func (s *Server) listReconCredentials(c *gin.Context) {
	x, e := s.Repo.ListReconCredentials(c)
	if e != nil {
		c.JSON(500, gin.H{"error": e.Error()})
		return
	}
	c.JSON(200, x)
}
func (s *Server) createReconCredential(c *gin.Context) {
	var x management.ReconCredentialSecret
	if c.ShouldBindJSON(&x) != nil || strings.TrimSpace(x.Name) == "" || x.Type != "ssh" || strings.TrimSpace(x.Username) == "" || (x.Password == "" && x.PrivateKey == "") {
		c.JSON(400, gin.H{"error": "name, SSH username and password or private key are required"})
		return
	}
	x.ID = credentialID()
	if e := s.Repo.SaveReconCredential(c, x); e != nil {
		c.JSON(500, gin.H{"error": e.Error()})
		return
	}
	c.JSON(201, gin.H{"id": x.ID, "name": x.Name, "type": x.Type, "username": x.Username, "created_at": time.Now().UTC()})
}
func (s *Server) deleteReconCredential(c *gin.Context) {
	if e := s.Repo.DeleteReconCredential(c, c.Param("id")); e != nil {
		c.JSON(500, gin.H{"error": e.Error()})
		return
	}
	c.JSON(200, gin.H{"deleted": true})
}
