package reporting

import (
	"os"

	"github.com/syslog-platform/logger/internal/models"
)

// ResolveTenantBranding resolves the effective logo path and branding details for a tenant.
func ResolveTenantBranding(tenantSlug, tenantName string) models.TenantBranding {
	branding := models.TenantBranding{
		TenantSlug: tenantSlug,
		TenantName: tenantName,
	}
	if tenantSlug != "" && tenantSlug != "default" {
		customPath := "/var/lib/logseal/tenants/" + tenantSlug + "/branding/logo.png"
		if _, err := os.Stat(customPath); err == nil {
			branding.CustomLogoPath = customPath
		}
	}
	// Fallback to default
	fallbackCandidates := []string{
		"/opt/syslog-platform/web/static/img/logseal_logo.png",
		"/opt/syslog-platform/web/static/images/logo.png",
		"web/static/img/logseal_logo.png",
		"web/static/images/logo.png",
	}
	for _, cand := range fallbackCandidates {
		if _, err := os.Stat(cand); err == nil {
			branding.DefaultLogoPath = cand
			break
		}
	}
	return branding
}
