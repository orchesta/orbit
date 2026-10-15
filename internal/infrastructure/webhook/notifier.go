package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/orchesta/orbit/internal/domain/entity"
)

// EventType represents the type of webhook event.
type EventType string

const (
	EventScanCompleted  EventType = "scan.completed"
	EventScanFailed     EventType = "scan.failed"
	EventVulnFound      EventType = "vulnerability.found"
	EventUpgradeCreated EventType = "upgrade.created"
)

// Payload is the webhook notification payload.
type Payload struct {
	Event     EventType   `json:"event"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// ScanEventData contains scan completion event data.
type ScanEventData struct {
	RepositoryID   string `json:"repository_id"`
	RepositoryName string `json:"repository_name"`
	ScanID         string `json:"scan_id"`
	Status         string `json:"status"`
	TotalDeps      int    `json:"total_deps"`
	OutdatedDeps   int    `json:"outdated_deps"`
	VulnerableDeps int    `json:"vulnerable_deps"`
	Duration       string `json:"duration"`
}

// VulnEventData contains vulnerability discovery event data.
type VulnEventData struct {
	RepositoryName string `json:"repository_name"`
	PackageName    string `json:"package_name"`
	OSVID          string `json:"osv_id"`
	Severity       string `json:"severity"`
	Summary        string `json:"summary"`
}

// UpgradeEventData contains auto-upgrade PR event data.
type UpgradeEventData struct {
	RepositoryName string `json:"repository_name"`
	PackageName    string `json:"package_name"`
	FromVersion    string `json:"from_version"`
	ToVersion      string `json:"to_version"`
	PRUrl          string `json:"pr_url"`
}

// Notifier sends webhook notifications to registered endpoints.
type Notifier struct {
	endpoints  []string
	httpClient *http.Client
	logger     *slog.Logger
}

// NewNotifier creates a new webhook notifier.
func NewNotifier(endpoints []string, logger *slog.Logger) *Notifier {
	return &Notifier{
		endpoints: endpoints,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger: logger,
	}
}

// NotifyScanCompleted sends a scan completion notification.
func (n *Notifier) NotifyScanCompleted(ctx context.Context, repo *entity.Repository, scan *entity.ScanResult) {
	event := EventScanCompleted
	if scan.Status == entity.ScanStatusFailed {
		event = EventScanFailed
	}

	n.send(ctx, Payload{
		Event:     event,
		Timestamp: time.Now().UTC(),
		Data: ScanEventData{
			RepositoryID:   repo.ID.String(),
			RepositoryName: repo.Name,
			ScanID:         scan.ID.String(),
			Status:         string(scan.Status),
			TotalDeps:      scan.TotalDeps,
			OutdatedDeps:   scan.OutdatedDeps,
			VulnerableDeps: scan.VulnerableDeps,
			Duration:       scan.Duration.String(),
		},
	})
}

// NotifyVulnerabilityFound sends a vulnerability discovery notification.
func (n *Notifier) NotifyVulnerabilityFound(ctx context.Context, repoName string, vuln *entity.Vulnerability, packageName string) {
	n.send(ctx, Payload{
		Event:     EventVulnFound,
		Timestamp: time.Now().UTC(),
		Data: VulnEventData{
			RepositoryName: repoName,
			PackageName:    packageName,
			OSVID:          vuln.OSVID,
			Severity:       string(vuln.Severity),
			Summary:        vuln.Summary,
		},
	})
}

// NotifyUpgradeCreated sends an auto-upgrade PR notification.
func (n *Notifier) NotifyUpgradeCreated(ctx context.Context, repoName string, packageName, from, to, prURL string) {
	n.send(ctx, Payload{
		Event:     EventUpgradeCreated,
		Timestamp: time.Now().UTC(),
		Data: UpgradeEventData{
			RepositoryName: repoName,
			PackageName:    packageName,
			FromVersion:    from,
			ToVersion:      to,
			PRUrl:          prURL,
		},
	})
}

// send dispatches the payload to all registered webhook endpoints.
func (n *Notifier) send(ctx context.Context, payload Payload) {
	if len(n.endpoints) == 0 {
		return
	}

	body, err := json.Marshal(payload)
	if err != nil {
		n.logger.Error("failed to marshal webhook payload", slog.String("error", err.Error()))
		return
	}

	for _, endpoint := range n.endpoints {
		go func(url string) {
			req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
			if err != nil {
				n.logger.Warn("failed to create webhook request",
					slog.String("url", url),
					slog.String("error", err.Error()),
				)
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Orbit-Event", string(payload.Event))

			resp, err := n.httpClient.Do(req)
			if err != nil {
				n.logger.Warn("webhook delivery failed",
					slog.String("url", url),
					slog.String("event", string(payload.Event)),
					slog.String("error", err.Error()),
				)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 400 {
				n.logger.Warn("webhook returned error",
					slog.String("url", url),
					slog.Int("status", resp.StatusCode),
				)
			} else {
				n.logger.Debug("webhook delivered",
					slog.String("url", url),
					slog.String("event", string(payload.Event)),
				)
			}
		}(endpoint)
	}
}

// SetEndpoints dynamically updates the webhook endpoints.
func (n *Notifier) SetEndpoints(endpoints []string) {
	n.endpoints = endpoints
}

// FormatSlackMessage creates a Slack-compatible message from a webhook payload.
func FormatSlackMessage(p Payload) map[string]interface{} {
	var text string
	switch data := p.Data.(type) {
	case ScanEventData:
		if p.Event == EventScanCompleted {
			text = fmt.Sprintf("✅ *Scan Complete* — `%s`\n📦 %d deps | ⬆️ %d outdated | 🛡️ %d vulnerable | ⏱️ %s",
				data.RepositoryName, data.TotalDeps, data.OutdatedDeps, data.VulnerableDeps, data.Duration)
		} else {
			text = fmt.Sprintf("❌ *Scan Failed* — `%s`\nStatus: %s", data.RepositoryName, data.Status)
		}
	case VulnEventData:
		text = fmt.Sprintf("🚨 *Vulnerability Found* — `%s`\n📦 %s | 🆔 %s | ⚠️ %s\n%s",
			data.RepositoryName, data.PackageName, data.OSVID, data.Severity, data.Summary)
	case UpgradeEventData:
		text = fmt.Sprintf("⬆️ *Auto-Upgrade PR* — `%s`\n📦 %s: %s → %s\n🔗 %s",
			data.RepositoryName, data.PackageName, data.FromVersion, data.ToVersion, data.PRUrl)
	}

	return map[string]interface{}{
		"text": text,
		"blocks": []map[string]interface{}{
			{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": text,
				},
			},
		},
	}
}
