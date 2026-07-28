package recon

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/management"
	"golang.org/x/crypto/ssh"
)

func probeAuthenticated(ctx context.Context, target string, p management.ReconPolicy, cred *management.ReconCredentialSecret) []management.ReconEvidence {
	if cred == nil || cred.Type != "ssh" {
		return nil
	}
	allowed := false
	for _, m := range p.AuthenticatedMethods {
		if strings.EqualFold(m, "ssh") {
			allowed = true
		}
	}
	if !allowed {
		return nil
	}
	var auth []ssh.AuthMethod
	if cred.PrivateKey != "" {
		if signer, err := ssh.ParsePrivateKey([]byte(cred.PrivateKey)); err == nil {
			auth = append(auth, ssh.PublicKeys(signer))
		}
	}
	if cred.Password != "" {
		auth = append(auth, ssh.Password(cred.Password))
	}
	if len(auth) == 0 || cred.Username == "" {
		return []management.ReconEvidence{evidence("authenticated.ssh", "missing usable credential", "ssh_inventory", 0)}
	}
	cfg := &ssh.ClientConfig{User: cred.Username, Auth: auth, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Duration(p.TimeoutSeconds) * time.Second}
	d := net.Dialer{Timeout: time.Duration(p.TimeoutSeconds) * time.Second}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(target, "22"))
	if err != nil {
		return nil
	}
	cc, chans, reqs, err := ssh.NewClientConn(raw, net.JoinHostPort(target, "22"), cfg)
	if err != nil {
		raw.Close()
		return []management.ReconEvidence{evidence("authenticated.ssh", "authentication failed", "ssh_inventory", 0)}
	}
	client := ssh.NewClient(cc, chans, reqs)
	defer client.Close()
	commands := []struct{ field, cmd string }{{"hostname", "hostname"}, {"operating_system", "uname -srm 2>/dev/null || cat /etc/os-release 2>/dev/null"}, {"model", "cat /sys/class/dmi/id/product_name 2>/dev/null"}, {"vendor", "cat /sys/class/dmi/id/sys_vendor 2>/dev/null"}, {"serial", "cat /sys/class/dmi/id/product_serial 2>/dev/null"}}
	var out []management.ReconEvidence
	for _, q := range commands {
		sess, e := client.NewSession()
		if e != nil {
			continue
		}
		b, e := sess.CombinedOutput(q.cmd)
		sess.Close()
		v := strings.TrimSpace(string(b))
		if e == nil && v != "" {
			if len(v) > 512 {
				v = v[:512]
			}
			out = append(out, evidence(q.field, v, "authenticated_ssh", 98))
		}
	}
	out = append(out, evidence("authenticated.method", fmt.Sprintf("ssh as %s", cred.Username), "authenticated_ssh", 100))
	return out
}
