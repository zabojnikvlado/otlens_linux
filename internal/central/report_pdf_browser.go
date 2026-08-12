package central

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// findPDFBrowser returns a Chromium-family browser suitable for headless
// print-to-PDF. OTLENS_CENTRAL_PDF_BROWSER can point at an explicit binary;
// otherwise common Chrome/Chromium/Edge names and Windows install paths are
// checked. The generated report HTML is self-contained, so the renderer never
// needs network access.
func findPDFBrowser() string {
	if explicit := strings.TrimSpace(os.Getenv("OTLENS_CENTRAL_PDF_BROWSER")); explicit != "" {
		if p, err := exec.LookPath(explicit); err == nil {
			return p
		}
		if info, err := os.Stat(explicit); err == nil && !info.IsDir() {
			return explicit
		}
	}
	for _, name := range []string{"chrome-headless-shell", "chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "microsoft-edge", "msedge", "chrome"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	if runtime.GOOS == "windows" {
		roots := uniqueNonEmpty([]string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LOCALAPPDATA")})
		for _, root := range roots {
			for _, rel := range []string{
				filepath.Join("Microsoft", "Edge", "Application", "msedge.exe"),
				filepath.Join("Google", "Chrome", "Application", "chrome.exe"),
			} {
				p := filepath.Join(root, rel)
				if info, err := os.Stat(p); err == nil && !info.IsDir() {
					return p
				}
			}
		}
	}
	return ""
}

func uniqueNonEmpty(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func localFileURL(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	p := filepath.ToSlash(abs)
	if runtime.GOOS == "windows" && !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return (&url.URL{Scheme: "file", Path: p}).String(), nil
}

// renderStyledReportPDF prints the exact saved report HTML through a headless
// Chromium-family browser. Unlike the legacy PDF writer (which intentionally
// reduced HTML to plain text), this preserves the hero, KPI cards, tables,
// severity pills, typography, spacing and print CSS visible in the web preview.
func renderStyledReportPDF(parent context.Context, htmlBody, reportID string) ([]byte, error) {
	browser := findPDFBrowser()
	if browser == "" {
		return nil, fmt.Errorf("no Chrome/Chromium/Edge renderer found; set OTLENS_CENTRAL_PDF_BROWSER")
	}
	dir, err := os.MkdirTemp("", "otlens-report-pdf-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	htmlPath := filepath.Join(dir, "report.html")
	pdfPath := filepath.Join(dir, "report.pdf")
	profilePath := filepath.Join(dir, "browser-profile")
	if err := os.WriteFile(htmlPath, []byte(htmlBody), 0o600); err != nil {
		return nil, err
	}
	inputURL, err := localFileURL(htmlPath)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	args := []string{
		"--headless",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--disable-background-networking",
		"--no-first-run",
		"--no-default-browser-check",
		"--user-data-dir=" + profilePath,
		"--no-pdf-header-footer",
		"--print-to-pdf-no-header",
		"--timeout=5000",
		"--print-to-pdf=" + pdfPath,
	}
	// Chromium refuses to run its sandbox as root on Linux. Production should
	// run Central unprivileged; this opt-in exists only for constrained service
	// environments where that is not possible.
	if strings.EqualFold(strings.TrimSpace(os.Getenv("OTLENS_CENTRAL_PDF_NO_SANDBOX")), "true") {
		args = append(args, "--no-sandbox")
	}
	args = append(args, inputURL)
	cmd := exec.CommandContext(ctx, browser, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("%s print-to-pdf failed: %w: %s", filepath.Base(browser), err, strings.TrimSpace(string(output)))
	}
	pdf, err := os.ReadFile(pdfPath)
	if err != nil {
		return nil, fmt.Errorf("read rendered PDF: %w", err)
	}
	if len(pdf) < 5 || string(pdf[:5]) != "%PDF-" {
		return nil, fmt.Errorf("browser returned an invalid PDF for %s", reportID)
	}
	return pdf, nil
}
