package correlation

import (
	"github.com/syslog-platform/logger/internal/models"
	"github.com/syslog-platform/logger/internal/siem/catalog"
)

// CatalogRules returns the complete 72-rule detection catalog across 12 distinct categories.
func CatalogRules() []models.SIEMRule {
	return catalog.Rules()
}
