package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/serverpars/parsvpn/internal/constants"
)

const userAgent = "parsvpn/" + constants.Version + " (+https://github.com/serverpars/parsvpn)"

// Release describes a GitHub release asset suitable for this host.
type Release struct {
	Tag          string
	Version      string
	Name         string
	Body         string
	AssetURL     string
	AssetName    string
	AssetDigest  string // "sha256:hex" from GitHub API when present
	HTMLURL      string
	PublishedAt  time.Time
}

type githubRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	HTMLURL     string    `json:"html_url"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Digest             string `json:"digest"`
		State              string `json:"state"`
	} `json:"assets"`
}

// Check fetches the latest stable GitHub release and compares it to current.
// Returns (nil, ErrNoUpdate) when already current.
func Check(ctx context.Context, current string) (*Release, error) {
	rel, err := fetchLatest(ctx)
	if err != nil {
		return nil, err
	}
	if !IsNewer(current, rel.Version) {
		return rel, ErrNoUpdate
	}
	return rel, nil
}

func fetchLatest(ctx context.Context) (*Release, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest",
		constants.GitHubOwner, constants.GitHubRepo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", userAgent)

	client := &http.Client{Timeout: constants.UpdateCheckTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github release check: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("github release check: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var gr githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		return nil, fmt.Errorf("decode release: %w", err)
	}
	if gr.Draft || gr.Prerelease {
		return nil, fmt.Errorf("latest release is draft/prerelease")
	}
	want := assetName()
	var assetURL, assetDigest, assetName string
	for _, a := range gr.Assets {
		if a.Name == want && (a.State == "" || a.State == "uploaded") {
			assetURL = a.BrowserDownloadURL
			assetDigest = a.Digest
			assetName = a.Name
			break
		}
	}
	if assetURL == "" {
		return nil, fmt.Errorf("release %s has no asset %s", gr.TagName, want)
	}
	return &Release{
		Tag:         gr.TagName,
		Version:     Normalize(gr.TagName),
		Name:        gr.Name,
		Body:        gr.Body,
		AssetURL:    assetURL,
		AssetName:   assetName,
		AssetDigest: assetDigest,
		HTMLURL:     gr.HTMLURL,
		PublishedAt: gr.PublishedAt,
	}, nil
}

func assetName() string {
	arch := runtime.GOARCH
	switch arch {
	case "amd64", "arm64":
	default:
		arch = runtime.GOARCH
	}
	return fmt.Sprintf("parsvpn-linux-%s", arch)
}

// Apply downloads rel, verifies checksum when present, replaces the installed
// binary, and restarts the systemd unit. Requires root.
func Apply(ctx context.Context, rel *Release) error {
	if rel == nil {
		return fmt.Errorf("nil release")
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("self-update is only supported on Linux")
	}
	dest, err := installPath()
	if err != nil {
		return err
	}
	tmp := dest + ".new"
	if err := downloadFile(ctx, rel.AssetURL, tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := verifyDigest(tmp, rel.AssetDigest); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// Replace atomically on the same filesystem. A running binary keeps its inode.
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install binary: %w (try running as root)", err)
	}
	if err := restartService(); err != nil {
		return fmt.Errorf("binary updated to %s but service restart failed: %w", FormatVersion(rel.Version), err)
	}
	return nil
}

// RunCheckAndApply checks for a newer release and applies it when auto is true
// or force is true. Returns the release (even on ErrNoUpdate).
func RunCheckAndApply(ctx context.Context, current string, auto, force bool) (*Release, error) {
	rel, err := Check(ctx, current)
	if err == ErrNoUpdate {
		return rel, ErrNoUpdate
	}
	if err != nil {
		return nil, err
	}
	if !auto && !force {
		return rel, nil
	}
	if err := Apply(ctx, rel); err != nil {
		return rel, err
	}
	return rel, nil
}

func installPath() (string, error) {
	if _, err := os.Stat(constants.InstallBin); err == nil {
		return constants.InstallBin, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

func downloadFile(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return f.Sync()
}

func verifyDigest(path, digest string) error {
	digest = strings.TrimSpace(digest)
	if digest == "" {
		return nil
	}
	const prefix = "sha256:"
	if !strings.HasPrefix(strings.ToLower(digest), prefix) {
		return fmt.Errorf("unsupported digest %q", digest)
	}
	wantHex := strings.TrimPrefix(strings.ToLower(digest), prefix)
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != wantHex {
		return fmt.Errorf("checksum mismatch: got %s want %s", got, wantHex)
	}
	return nil
}

func restartService() error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil // binary replaced; no systemd in this environment
	}
	cmd := exec.Command("systemctl", "restart", constants.ServiceName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
