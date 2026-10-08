package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/syslog-platform/logger/internal/models"
	"github.com/syslog-platform/logger/internal/version"
)

type UpdateStatusResponse struct {
	Platform       string `json:"platform"`
	CurrentVersion string `json:"current_version"`
	CurrentCommit  string `json:"current_commit"`
	BuildDate      string `json:"build_date"`
	Repository     string `json:"repository"`
	Branch         string `json:"branch"`
	RepoURL        string `json:"repo_url"`
}

type GitHubCommit struct {
	SHA    string `json:"sha"`
	Commit struct {
		Message string `json:"message"`
		Author  struct {
			Name string    `json:"name"`
			Date time.Time `json:"date"`
		} `json:"author"`
	} `json:"commit"`
	HTMLURL string `json:"html_url"`
}

type ChangedFile struct {
	Filename    string `json:"filename"`
	Status      string `json:"status"` // "modified", "added", "removed"
	Additions   int    `json:"additions"`
	Deletions   int    `json:"deletions"`
	CanHotApply bool   `json:"can_hot_apply"` // true for web templates, static assets, docs
}

type UpdateCheckResponse struct {
	HasUpdate     bool          `json:"has_update"`
	CurrentCommit string        `json:"current_commit"`
	LatestCommit  *GitHubCommit `json:"latest_commit,omitempty"`
	CommitsBehind int           `json:"commits_behind"`
	ChangedFiles  []ChangedFile `json:"changed_files"`
	CommitHistory []string      `json:"commit_history"`
	BinaryChanged bool          `json:"binary_changed"`
	LastChecked   time.Time     `json:"last_checked"`
	Message       string        `json:"message"`
}

type UpdateApplyResponse struct {
	Success        bool     `json:"success"`
	UpdatedFiles   []string `json:"updated_files"`
	SkippedFiles   []string `json:"skipped_files"`
	BinaryChanged  bool     `json:"binary_changed"`
	NewCommit      string   `json:"new_commit"`
	Message        string   `json:"message"`
	CLIInstruction string   `json:"cli_instruction"`
}

func (h *Handler) handleSystemUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	_, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	writeJSON(w, http.StatusOK, UpdateStatusResponse{
		Platform:       version.Platform,
		CurrentVersion: version.Version,
		CurrentCommit:  version.CommitSHA,
		BuildDate:      version.BuildDate,
		Repository:     fmt.Sprintf("%s/%s", version.RepoOwner, version.RepoName),
		Branch:         version.Branch,
		RepoURL:        fmt.Sprintf("https://github.com/%s/%s", version.RepoOwner, version.RepoName),
	})
}

func (h *Handler) handleSystemUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	_, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	// 1. Fetch latest commit from GitHub repository
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s", version.RepoOwner, version.RepoName, version.Branch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	req.Header.Set("User-Agent", "Valtrivo-LogSeal-Updater/1.0")
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "Failed contacting GitHub API: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": fmt.Sprintf("GitHub API error (status %d): %s", resp.StatusCode, string(body)),
		})
		return
	}

	var latestCommit GitHubCommit
	if err := json.NewDecoder(resp.Body).Decode(&latestCommit); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed parsing GitHub response: " + err.Error()})
		return
	}

	currentShort := strings.ToLower(version.CommitSHA)
	latestShort := strings.ToLower(latestCommit.SHA)
	if len(latestShort) > 7 {
		latestShort = latestShort[:7]
	}
	if len(currentShort) > 7 {
		currentShort = currentShort[:7]
	}

	// 2. Check if already up to date
	if currentShort == latestShort || strings.HasPrefix(strings.ToLower(latestCommit.SHA), currentShort) {
		writeJSON(w, http.StatusOK, UpdateCheckResponse{
			HasUpdate:     false,
			CurrentCommit: version.CommitSHA,
			LatestCommit:  &latestCommit,
			CommitsBehind: 0,
			ChangedFiles:  []ChangedFile{},
			BinaryChanged: false,
			LastChecked:   time.Now().UTC(),
			Message:       "System is up to date! You are running the latest version from origin/main.",
		})
		return
	}

	// 3. Query commit comparison between current and latest
	compareURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/compare/%s...%s",
		version.RepoOwner, version.RepoName, version.CommitSHA, latestCommit.SHA)
	compReq, err := http.NewRequestWithContext(ctx, http.MethodGet, compareURL, nil)
	var changedFiles []ChangedFile
	var commitHistory []string
	commitsBehind := 1
	binaryChanged := false

	if err == nil {
		compReq.Header.Set("User-Agent", "Valtrivo-LogSeal-Updater/1.0")
		compReq.Header.Set("Accept", "application/vnd.github.v3+json")
		if compResp, compErr := http.DefaultClient.Do(compReq); compErr == nil {
			defer compResp.Body.Close()
			if compResp.StatusCode == http.StatusOK {
				var compData struct {
					TotalCommits int `json:"total_commits"`
					Commits      []struct {
						SHA    string `json:"sha"`
						Commit struct {
							Message string `json:"message"`
						} `json:"commit"`
					} `json:"commits"`
					Files []struct {
						Filename  string `json:"filename"`
						Status    string `json:"status"`
						Additions int    `json:"additions"`
						Deletions int    `json:"deletions"`
					} `json:"files"`
				}
				if json.NewDecoder(compResp.Body).Decode(&compData) == nil {
					commitsBehind = compData.TotalCommits
					for _, c := range compData.Commits {
						msg := strings.Split(c.Commit.Message, "\n")[0]
						shaPrefix := c.SHA
						if len(shaPrefix) > 7 {
							shaPrefix = shaPrefix[:7]
						}
						commitHistory = append(commitHistory, fmt.Sprintf("%s: %s", shaPrefix, msg))
					}
					for _, f := range compData.Files {
						isHot := isHotApplicable(f.Filename)
						if !isHot && (strings.HasPrefix(f.Filename, "cmd/") || strings.HasPrefix(f.Filename, "internal/") || f.Filename == "go.mod" || f.Filename == "Dockerfile") {
							binaryChanged = true
						}
						changedFiles = append(changedFiles, ChangedFile{
							Filename:    f.Filename,
							Status:      f.Status,
							Additions:   f.Additions,
							Deletions:   f.Deletions,
							CanHotApply: isHot,
						})
					}
				}
			}
		}
	}

	// Fallback if compare API returned nothing
	if len(changedFiles) == 0 {
		commitHistory = append(commitHistory, strings.Split(latestCommit.Commit.Message, "\n")[0])
	}

	writeJSON(w, http.StatusOK, UpdateCheckResponse{
		HasUpdate:     true,
		CurrentCommit: version.CommitSHA,
		LatestCommit:  &latestCommit,
		CommitsBehind: commitsBehind,
		ChangedFiles:  changedFiles,
		CommitHistory: commitHistory,
		BinaryChanged: binaryChanged,
		LastChecked:   time.Now().UTC(),
		Message:       fmt.Sprintf("Update available: %d new commit(s) on origin/main", commitsBehind),
	})
}

func (h *Handler) handleSystemUpdateApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	flusher, isFlusher := w.(http.Flusher)
	isStream := strings.Contains(r.Header.Get("Accept"), "text/event-stream") && isFlusher

	if isStream {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, no-transform")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
	}

	sendProgress := func(pct int, stage, msg string, done, success bool, extra map[string]interface{}) {
		if !isStream {
			return
		}
		payload := map[string]interface{}{
			"percent": pct,
			"stage":   stage,
			"message": msg,
			"time":    time.Now().Format("15:04:05"),
			"done":    done,
			"success": success,
		}
		for k, v := range extra {
			payload[k] = v
		}
		data, _ := json.Marshal(payload)
		fmt.Fprintf(w, "data: %s\n\n", string(data))
		flusher.Flush()
	}

	sendProgress(5, "INIT", "Initializing platform upgrade engine...", false, true, nil)

	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()

	// 1. Fetch latest commit info from GitHub
	sendProgress(12, "GITHUB_CHECK", fmt.Sprintf("Connecting to GitHub API (%s/%s on branch %s)...", version.RepoOwner, version.RepoName, version.Branch), false, true, nil)
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s", version.RepoOwner, version.RepoName, version.Branch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		sendProgress(0, "ERROR", "Failed to build GitHub request: "+err.Error(), true, false, nil)
		if !isStream {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return
	}
	req.Header.Set("User-Agent", "Valtrivo-LogSeal-Updater/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		sendProgress(0, "ERROR", "Failed contacting GitHub API: "+err.Error(), true, false, nil)
		if !isStream {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "Failed contacting GitHub: " + err.Error()})
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		errMsg := fmt.Sprintf("GitHub API returned HTTP %d: %s", resp.StatusCode, string(body))
		sendProgress(0, "ERROR", errMsg, true, false, nil)
		if !isStream {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": errMsg})
		}
		return
	}

	var latest GitHubCommit
	if err := json.NewDecoder(resp.Body).Decode(&latest); err != nil {
		sendProgress(0, "ERROR", "Failed decoding GitHub commit metadata: "+err.Error(), true, false, nil)
		if !isStream {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed decoding commit: " + err.Error()})
		}
		return
	}

	shortSHA := latest.SHA
	if len(shortSHA) > 7 {
		shortSHA = shortSHA[:7]
	}
	commitMsg := latest.Commit.Message
	if idx := strings.Index(commitMsg, "\n"); idx != -1 {
		commitMsg = commitMsg[:idx]
	}

	sendProgress(25, "COMMIT_RESOLVED", fmt.Sprintf("Target remote commit: %s (\"%s\")", shortSHA, commitMsg), false, true, nil)

	// 2. If local git CLI is present and workspace is a git repository, try running git pull
	sendProgress(35, "GIT_SYNC", "Checking local Git repository status...", false, true, nil)
	gitSuccess := false
	if _, gitErr := exec.LookPath("git"); gitErr == nil {
		sendProgress(40, "GIT_PULL", "Local Git CLI detected. Executing 'git pull origin "+version.Branch+"'...", false, true, nil)
		cmd := exec.CommandContext(ctx, "git", "pull", "origin", version.Branch)
		if out, err := cmd.CombinedOutput(); err == nil && !strings.Contains(string(out), "error") {
			gitSuccess = true
			sendProgress(50, "GIT_PULL", fmt.Sprintf("Git pull successful: %s", strings.TrimSpace(string(out))), false, true, nil)
		} else {
			sendProgress(50, "GIT_PULL", "Git pull notice: "+strings.TrimSpace(string(out))+"; proceeding with raw asset sync.", false, true, nil)
		}
	} else {
		sendProgress(50, "GIT_SYNC", "Container running without git CLI; streaming raw file updates directly.", false, true, nil)
	}

	// 3. Pull files from GitHub raw contents
	hotPaths := []string{
		"web/static/js/app.js",
		"web/static/js/translations.js",
		"web/static/js/i18n.js",
		"web/static/css/dashboard.css",
		"web/templates/index.html",
		"web/templates/login.html",
		"internal/version/version.go",
		"upgrade.sh",
		"produce-logs.sh",
		"HOW_TO_INSTALL.md",
		"HOW_TO_INSTALL.en.md",
		"HOW_TO_INSTALL.tr.md",
		"UPGRADE.md",
		"README.md",
		"README.tr.md",
		"docs/ARCHITECTURE.md",
		"docs/MITRE_ATTACK_GUIDE.md",
		"migrations/postgres/001_initial_schema.sql",
		"migrations/postgres/002_siem_tables.sql",
		"migrations/clickhouse/001_initial_events.sql",
		"docker-compose.yml",
	}

	var updatedFiles []string
	var skippedFiles []string
	binaryChanged := false

	for i, relPath := range hotPaths {
		pct := 50 + int(float64(i+1)/float64(len(hotPaths))*35) // 50% -> 85%
		rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s",
			version.RepoOwner, version.RepoName, version.Branch, relPath)

		rawReq, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			skippedFiles = append(skippedFiles, relPath)
			continue
		}
		rawReq.Header.Set("User-Agent", "Valtrivo-LogSeal-Updater/1.0")

		rawResp, err := http.DefaultClient.Do(rawReq)
		if err != nil || rawResp.StatusCode != http.StatusOK {
			if rawResp != nil {
				rawResp.Body.Close()
			}
			skippedFiles = append(skippedFiles, relPath)
			continue
		}

		content, err := io.ReadAll(rawResp.Body)
		rawResp.Body.Close()
		if err != nil {
			skippedFiles = append(skippedFiles, relPath)
			continue
		}

		// Write to possible target locations in container and local filesystem
		targets := []string{
			filepath.Join("/opt/syslog-platform", relPath),
			relPath,
		}
		wroteAny := false
		for _, tgt := range targets {
			if dir := filepath.Dir(tgt); dir != "." {
				_ = os.MkdirAll(dir, 0755)
			}
			if err := os.WriteFile(tgt, content, 0644); err == nil {
				wroteAny = true
			}
		}
		if wroteAny {
			updatedFiles = append(updatedFiles, relPath)
			sendProgress(pct, "HOT_PATCH", fmt.Sprintf("Hot-patched %s (%d bytes)", relPath, len(content)), false, true, nil)
		} else {
			skippedFiles = append(skippedFiles, relPath)
		}
	}

	// 4. Update runtime version configuration
	version.CommitSHA = shortSHA

	// Attempt to extract updated version from updated internal/version/version.go
	for _, p := range []string{"internal/version/version.go", "/opt/syslog-platform/internal/version/version.go"} {
		if data, err := os.ReadFile(p); err == nil {
			re := regexp.MustCompile(`Version\s*=\s*"([^"]+)"`)
			if m := re.FindStringSubmatch(string(data)); len(m) > 1 && m[1] != "" {
				version.Version = m[1]
				break
			}
		}
	}

	sendProgress(90, "VERSION_STATE", fmt.Sprintf("Updated runtime version state to %s (%s)", version.Version, shortSHA), false, true, nil)

	versionInfoContent := fmt.Sprintf("COMMIT_SHA=%s\nVERSION=%s\nBUILD_DATE=%s\nUPDATED_AT=%s\nUPDATED_BY=%s\n",
		shortSHA, version.Version, time.Now().Format("2006-01-02"), time.Now().UTC().Format(time.RFC3339), session.Username)

	_ = os.WriteFile("/opt/syslog-platform/config/.version_info", []byte(versionInfoContent), 0644)
	_ = os.WriteFile("config/.version_info", []byte(versionInfoContent), 0644)

	// 5. Record audit log
	sendProgress(95, "AUDIT_LOG", "Recording upgrade event in system audit trail...", false, true, nil)
	auditEntry := &models.AuditLog{
		Username: session.Username,
		SourceIP: r.RemoteAddr,
		Action:   "SYSTEM_UPGRADE_APPLIED",
		Resource: "SYSTEM",
		Result:   "SUCCESS",
		Details: map[string]interface{}{
			"new_commit":    shortSHA,
			"files_updated": len(updatedFiles),
			"git_pulled":    gitSuccess,
			"version":       version.Version,
		},
		CreatedAt: time.Now().UTC(),
	}
	_ = h.pgDB.InsertAuditLog(ctx, auditEntry)

	msg := fmt.Sprintf("Upgrade completed successfully! %d files hot-patched to %s (%s).", len(updatedFiles), version.Version, shortSHA)
	cliCmd := "sudo bash upgrade.sh\n# or\ngit pull origin main && docker compose build syslog-app && docker compose up -d"

	sendProgress(100, "COMPLETE", msg, true, true, map[string]interface{}{
		"new_version":     version.Version,
		"new_commit":      shortSHA,
		"updated_files":   len(updatedFiles),
		"cli_instruction": cliCmd,
	})

	if !isStream {
		writeJSON(w, http.StatusOK, UpdateApplyResponse{
			Success:        true,
			UpdatedFiles:   updatedFiles,
			SkippedFiles:   skippedFiles,
			BinaryChanged:  binaryChanged,
			NewCommit:      shortSHA,
			Message:        msg,
			CLIInstruction: cliCmd,
		})
	}
}

// isHotApplicable checks if a file can be updated live without recompiling the Go binary
func isHotApplicable(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	if ext == ".html" || ext == ".js" || ext == ".css" || ext == ".md" || ext == ".sh" || ext == ".sql" || ext == ".png" || ext == ".svg" {
		return true
	}
	if strings.HasPrefix(filename, "web/") || strings.HasPrefix(filename, "migrations/") || strings.HasPrefix(filename, "docs/") {
		return true
	}
	return false
}
