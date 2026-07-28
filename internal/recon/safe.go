package recon

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/management"
)

func Run(ctx context.Context, cmd management.ReconCommand) []management.ReconResult {
	p := cmd.Policy
	if p.TimeoutSeconds <= 0 {
		p.TimeoutSeconds = 3
	}
	if p.PacketsPerSecond <= 0 {
		p.PacketsPerSecond = 5
	}
	if len(p.Ports) == 0 {
		p.Ports = []int{22, 80, 443, 445, 3389, 502, 102, 44818, 4840}
	}
	delay := time.Second / time.Duration(p.PacketsPerSecond)
	out := make([]management.ReconResult, 0, len(cmd.Targets))
	for _, target := range cmd.Targets {
		select {
		case <-ctx.Done():
			return out
		default:
		}
		out = append(out, probeTarget(ctx, strings.TrimSpace(target), p, cmd.Credential, delay))
	}
	return out
}

func probeTarget(ctx context.Context, target string, p management.ReconPolicy, cred *management.ReconCredentialSecret, delay time.Duration) management.ReconResult {
	r := management.ReconResult{Target: target, StartedAt: time.Now().UTC()}
	defer func() { r.FinishedAt = time.Now().UTC() }()
	ip := net.ParseIP(target)
	if ip == nil {
		r.Error = "invalid IP address"
		return r
	}
	if denied(ip, p) {
		r.Error = "blocked by reconnaissance policy"
		return r
	}
	if names, err := net.DefaultResolver.LookupAddr(ctx, target); err == nil && len(names) > 0 {
		r.Hostname = strings.TrimSuffix(names[0], ".")
		r.Evidence = append(r.Evidence, evidence("hostname", r.Hostname, "reverse_dns", 75))
	}
	ports := append([]int(nil), p.Ports...)
	sort.Ints(ports)
	for _, port := range ports {
		select {
		case <-ctx.Done():
			r.Error = ctx.Err().Error()
			return r
		case <-time.After(delay):
		}
		svc, ok := probePort(ctx, target, port, time.Duration(p.TimeoutSeconds)*time.Second)
		if ok {
			r.Reachable = true
			r.Services = append(r.Services, svc)
			enrich(&r, svc)
		}
	}
	if strings.EqualFold(cmdProfile(p), "ot-conservative") || len(p.OTProtocols) > 0 {
		otEvidence := probeOTIdentity(ctx, target, p.OTProtocols, time.Duration(p.TimeoutSeconds)*time.Second)
		if len(otEvidence) > 0 {
			r.Reachable = true
			r.Evidence = append(r.Evidence, otEvidence...)
			if r.OTIdentity == nil {
				r.OTIdentity = map[string]string{}
			}
			for _, ev := range otEvidence {
				k := strings.TrimPrefix(ev.Field, "ot.")
				r.OTIdentity[k] = ev.Value
				switch k {
				case "vendor":
					if r.Vendor == "" {
						r.Vendor = ev.Value
					}
				case "product", "product_name", "model":
					if r.Model == "" {
						r.Model = ev.Value
					}
				case "firmware":
					if r.Firmware == "" {
						r.Firmware = ev.Value
					}
				case "serial":
					if r.Serial == "" {
						r.Serial = ev.Value
					}
				}
			}
		}
	}
	if cred != nil {
		authEvidence := probeAuthenticated(ctx, target, p, cred)
		for _, ev := range authEvidence {
			r.Evidence = append(r.Evidence, ev)
			switch ev.Field {
			case "hostname":
				r.Hostname = ev.Value
			case "vendor":
				r.Vendor = ev.Value
			case "model":
				r.Model = ev.Value
			case "operating_system":
				r.OS = ev.Value
			case "serial":
				r.Serial = ev.Value
			}
		}
		if len(authEvidence) > 0 {
			r.Reachable = true
		}
	}
	if !r.Reachable && r.Error == "" {
		r.Error = "no configured service responded"
	}
	return r
}

func cmdProfile(p management.ReconPolicy) string {
	if len(p.OTProtocols) > 0 {
		return "ot-conservative"
	}
	return "safe-discovery"
}

func denied(ip net.IP, p management.ReconPolicy) bool {
	for _, s := range p.DeniedTargets {
		if x := net.ParseIP(strings.TrimSpace(s)); x != nil && x.Equal(ip) {
			return true
		}
	}
	if len(p.AllowedNetworks) == 0 {
		return false
	}
	for _, s := range p.AllowedNetworks {
		if _, n, e := net.ParseCIDR(strings.TrimSpace(s)); e == nil && n.Contains(ip) {
			return false
		}
	}
	return true
}

func probePort(ctx context.Context, host string, port int, timeout time.Duration) (management.ReconService, bool) {
	s := management.ReconService{Port: port, Transport: "tcp", Service: serviceName(port)}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return s, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	switch port {
	case 22:
		line, _ := bufio.NewReader(conn).ReadString('\n')
		s.Banner = strings.TrimSpace(line)
		parseSSH(&s)
	case 80:
		req, _ := http.NewRequestWithContext(ctx, http.MethodHead, "http://"+net.JoinHostPort(host, "80")+"/", nil)
		cli := http.Client{Timeout: timeout}
		if resp, e := cli.Do(req); e == nil {
			s.Product = resp.Header.Get("Server")
			resp.Body.Close()
		}
	case 443:
		_ = conn.Close()
		tc, e := tls.DialWithDialer(&d, "tcp", net.JoinHostPort(host, "443"), &tls.Config{InsecureSkipVerify: true, ServerName: host})
		if e == nil {
			st := tc.ConnectionState()
			if len(st.PeerCertificates) > 0 {
				c := st.PeerCertificates[0]
				s.TLSSubject = c.Subject.String()
				s.TLSIssuer = c.Issuer.String()
			}
			tc.Close()
		}
	}
	return s, true
}

func serviceName(p int) string {
	m := map[int]string{22: "ssh", 80: "http", 443: "https", 445: "smb", 3389: "rdp", 502: "modbus", 102: "s7comm", 44818: "ethernet-ip", 4840: "opc-ua"}
	if x := m[p]; x != "" {
		return x
	}
	return "unknown"
}
func parseSSH(s *management.ReconService) {
	if strings.HasPrefix(s.Banner, "SSH-") {
		s.Product = s.Banner
	}
}
func evidence(field, value, source string, confidence int) management.ReconEvidence {
	return management.ReconEvidence{Field: field, Value: value, Source: source, Confidence: confidence, ObservedAt: time.Now().UTC()}
}
func enrich(r *management.ReconResult, s management.ReconService) {
	if s.Product != "" {
		r.Evidence = append(r.Evidence, evidence("service."+s.Service, s.Product, "active_banner", 80))
	}
	if s.Service == "smb" {
		r.OS = "Windows or SMB-compatible system"
		r.Evidence = append(r.Evidence, evidence("operating_system", r.OS, "smb_service", 45))
	}
	if s.Service == "s7comm" {
		r.Vendor = "Siemens"
		r.Evidence = append(r.Evidence, evidence("vendor", r.Vendor, "s7_service", 60))
	}
}
