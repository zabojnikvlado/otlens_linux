package recon

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
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
		out = append(out, probeTarget(ctx, strings.TrimSpace(target), cmd.Profile, p, cmd.Credential, delay))
	}
	return out
}

func audit(r *management.ReconResult, stage, status, detail string) {
	r.Audit = append(r.Audit, management.ReconAuditStep{Stage: stage, Status: status, Detail: detail, ObservedAt: time.Now().UTC()})
}

func probeTarget(ctx context.Context, target, profile string, p management.ReconPolicy, cred *management.ReconCredentialSecret, delay time.Duration) (r management.ReconResult) {
	r = management.ReconResult{Target: target, StartedAt: time.Now().UTC()}
	audit(&r, "sensor_received", "ok", "discovery command accepted by sensor")
	defer func() { r.FinishedAt = time.Now().UTC() }()
	ip := net.ParseIP(target)
	if ip == nil {
		r.Error = "invalid IP address"
		audit(&r, "policy_validation", "failed", r.Error)
		return r
	}
	if denied(ip, p) {
		r.Error = "blocked by reconnaissance policy"
		audit(&r, "policy_validation", "failed", r.Error)
		return r
	}
	audit(&r, "policy_validation", "ok", "target permitted by policy")
	if names, err := net.DefaultResolver.LookupAddr(ctx, target); err == nil && len(names) > 0 {
		r.Hostname = strings.TrimSuffix(names[0], ".")
		r.Evidence = append(r.Evidence, evidence("hostname", r.Hostname, "reverse_dns", 75))
		audit(&r, "reverse_dns", "ok", r.Hostname)
	} else if err != nil {
		audit(&r, "reverse_dns", "warning", err.Error())
	} else {
		audit(&r, "reverse_dns", "warning", "no PTR record")
	}

	ports := append([]int(nil), p.Ports...)
	sort.Ints(ports)
	open := 0
	for _, port := range ports {
		select {
		case <-ctx.Done():
			r.Error = ctx.Err().Error()
			audit(&r, "port_scan", "failed", r.Error)
			return r
		case <-time.After(delay):
		}
		svc, ok := probePort(ctx, target, port, time.Duration(p.TimeoutSeconds)*time.Second)
		if ok {
			open++
			r.Reachable = true
			r.Services = append(r.Services, svc)
			r.Evidence = append(r.Evidence, evidence("service.open", fmt.Sprintf("%s/%d", svc.Service, svc.Port), "tcp_connect", 100))
			enrich(&r, svc)
		}
	}
	if open > 0 {
		audit(&r, "port_scan", "ok", fmt.Sprintf("%d of %d configured TCP ports open", open, len(ports)))
	} else {
		audit(&r, "port_scan", "warning", fmt.Sprintf("no response on %d configured TCP ports", len(ports)))
	}
	if len(r.Services) > 0 {
		audit(&r, "service_enumeration", "ok", serviceSummary(r.Services))
	} else {
		audit(&r, "service_enumeration", "warning", "no service banners or open ports collected")
	}

	if strings.EqualFold(profile, "ot-conservative") || len(p.OTProtocols) > 0 {
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
			audit(&r, "protocol_probes", "ok", fmt.Sprintf("%d OT identity facts", len(otEvidence)))
		} else {
			audit(&r, "protocol_probes", "warning", "no OT identity response")
		}
	} else {
		audit(&r, "protocol_probes", "skipped", "OT protocol probes not requested")
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
			audit(&r, "authenticated_inventory", "ok", fmt.Sprintf("%d facts collected", len(authEvidence)))
		} else {
			audit(&r, "authenticated_inventory", "warning", "credentialed probe returned no facts")
		}
	} else {
		audit(&r, "authenticated_inventory", "skipped", "no credential supplied")
	}

	facts := 0
	for _, v := range []string{r.Hostname, r.Vendor, r.OS, r.Model, r.Firmware, r.Serial} {
		if v != "" {
			facts++
		}
	}
	if facts > 0 || len(r.Services) > 0 {
		audit(&r, "asset_enrichment", "ok", fmt.Sprintf("%d identity fields and %d services", facts, len(r.Services)))
	} else {
		audit(&r, "asset_enrichment", "warning", "target responded without identifiable metadata")
	}
	if !r.Reachable && r.Error == "" {
		r.Error = "no configured service responded"
	}
	return r
}

func serviceSummary(services []management.ReconService) string {
	parts := make([]string, 0, len(services))
	for _, s := range services {
		d := fmt.Sprintf("%d/%s", s.Port, s.Service)
		if s.Product != "" {
			d += " " + s.Product
		}
		parts = append(parts, d)
	}
	return strings.Join(parts, ", ")
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
		probeHTTP(ctx, &s, "http://"+net.JoinHostPort(host, fmt.Sprint(port))+"/", timeout)
	case 443:
		_ = conn.Close()
		tc, e := tls.DialWithDialer(&d, "tcp", net.JoinHostPort(host, fmt.Sprint(port)), &tls.Config{InsecureSkipVerify: true, ServerName: host})
		if e == nil {
			st := tc.ConnectionState()
			if len(st.PeerCertificates) > 0 {
				c := st.PeerCertificates[0]
				s.TLSSubject = c.Subject.String()
				s.TLSIssuer = c.Issuer.String()
				s.Hostname = certificateHostname(c)
			}
			tc.Close()
		}
	}
	return s, true
}

func probeHTTP(ctx context.Context, s *management.ReconService, url string, timeout time.Duration) {
	cli := http.Client{Timeout: timeout}
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	resp, err := cli.Do(req)
	if err == nil {
		s.Product = resp.Header.Get("Server")
		s.Hostname = responseHostname(resp)
		resp.Body.Close()
		if s.Product != "" || s.Hostname != "" {
			return
		}
	}
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Range", "bytes=0-0")
	if resp, err = cli.Do(req); err == nil {
		s.Product = resp.Header.Get("Server")
		s.Hostname = responseHostname(resp)
		resp.Body.Close()
	}
}

func responseHostname(resp *http.Response) string {
	if resp == nil || resp.Request == nil || resp.Request.URL == nil {
		return ""
	}
	return usableHostname(resp.Request.URL.Hostname())
}

func certificateHostname(c *x509.Certificate) string {
	if c == nil {
		return ""
	}
	for _, name := range c.DNSNames {
		if h := usableHostname(name); h != "" {
			return h
		}
	}
	return usableHostname(c.Subject.CommonName)
}

func usableHostname(value string) string {
	h := strings.TrimSuffix(strings.TrimSpace(value), ".")
	h = strings.TrimPrefix(h, "*.")
	if h == "" || net.ParseIP(h) != nil || !strings.Contains(h, ".") {
		return ""
	}
	return h
}

func serviceName(p int) string {
	m := map[int]string{22: "ssh", 80: "http", 443: "https", 445: "smb", 3389: "rdp", 502: "modbus", 102: "s7comm", 44818: "ethernet-ip", 4840: "opc-ua"}
	if x := m[p]; x != "" {
		return x
	}
	return "unknown"
}
func parseSSH(s *management.ReconService) {
	if !strings.HasPrefix(s.Banner, "SSH-") {
		return
	}
	s.Product = s.Banner
	lower := strings.ToLower(s.Banner)
	if i := strings.Index(lower, "openssh_"); i >= 0 {
		tail := s.Banner[i+len("OpenSSH_"):]
		s.Version = strings.Fields(tail)[0]
	}
}
func evidence(field, value, source string, confidence int) management.ReconEvidence {
	return management.ReconEvidence{Field: field, Value: value, Source: source, Confidence: confidence, ObservedAt: time.Now().UTC()}
}
func enrich(r *management.ReconResult, s management.ReconService) {
	if r.Hostname == "" && s.Hostname != "" {
		r.Hostname = s.Hostname
		r.Evidence = append(r.Evidence, evidence("hostname", r.Hostname, serviceHostnameSource(s), 70))
	}
	if s.Product != "" {
		r.Evidence = append(r.Evidence, evidence("service."+s.Service, s.Product, "active_banner", 80))
	}
	lower := strings.ToLower(s.Banner + " " + s.Product)
	if s.Service == "ssh" {
		if strings.Contains(lower, "ubuntu") {
			r.OS = "Ubuntu Linux"
			if idx := strings.Index(lower, "ubuntu-"); idx >= 0 {
				token := strings.Fields((s.Banner + " " + s.Product)[idx+len("ubuntu-"):])
				if len(token) > 0 {
					r.OS = "Ubuntu Linux (OpenSSH package " + token[0] + ")"
				}
			}
			r.Evidence = append(r.Evidence, evidence("operating_system", r.OS, "ssh_banner", 85))
		} else if strings.Contains(lower, "debian") {
			r.OS = "Debian Linux"
			r.Evidence = append(r.Evidence, evidence("operating_system", r.OS, "ssh_banner", 80))
		}
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

func serviceHostnameSource(s management.ReconService) string {
	if s.Service == "https" {
		return "tls_certificate"
	}
	if s.Service == "http" {
		return "http_redirect"
	}
	return "service_probe"
}
