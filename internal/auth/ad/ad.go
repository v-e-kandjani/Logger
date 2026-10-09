package ad

import (
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Config represents Active Directory / LDAP connection settings
type Config struct {
	Enabled            bool          `json:"enabled"`
	Server             string        `json:"server"`               // Hostname or IP
	Port               int           `json:"port"`                 // 389 (LDAP) or 636 (LDAPS)
	UseSSL             bool          `json:"use_ssl"`              // Direct LDAPS
	StartTLS           bool          `json:"start_tls"`            // StartTLS on port 389
	InsecureSkipVerify bool          `json:"insecure_skip_verify"` // Skip TLS verification for self-signed domain certs
	BaseDN             string        `json:"base_dn"`              // e.g. DC=corp,DC=local
	BindDN             string        `json:"bind_dn"`              // e.g. CN=svc-logger,OU=Service,DC=corp,DC=local or svc-logger@corp.local
	BindPassword       string        `json:"bind_password"`        // Service account password
	UserFilter         string        `json:"user_filter"`          // e.g. (&(objectCategory=person)(objectClass=user))
	UsernameAttr       string        `json:"username_attr"`        // sAMAccountName
	NameAttr           string        `json:"name_attr"`            // displayName
	EmailAttr          string        `json:"email_attr"`           // mail
	DefaultRole        string        `json:"default_role"`         // Role assigned upon sync (e.g. Security Analyst)
	Timeout            time.Duration `json:"timeout"`
}

// User represents an Active Directory user account discovered from the directory
type User struct {
	Username    string   `json:"username"`
	FullName    string   `json:"full_name"`
	Email       string   `json:"email"`
	DN          string   `json:"dn"`
	MemberOf    []string `json:"member_of"`
	Role        string   `json:"role"`
	IsEnabled   bool     `json:"is_enabled"`
}

// Client interacts with the Active Directory domain controller
type Client struct {
	cfg Config
}

// NewClient creates an Active Directory client with the specified configuration
func NewClient(cfg Config) *Client {
	if cfg.Port <= 0 {
		if cfg.UseSSL {
			cfg.Port = 636
		} else {
			cfg.Port = 389
		}
	}
	if cfg.UsernameAttr == "" {
		cfg.UsernameAttr = "sAMAccountName"
	}
	if cfg.NameAttr == "" {
		cfg.NameAttr = "displayName"
	}
	if cfg.EmailAttr == "" {
		cfg.EmailAttr = "mail"
	}
	if cfg.DefaultRole == "" {
		cfg.DefaultRole = "Security Analyst"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &Client{cfg: cfg}
}

// LoadConfigFromSettings populates Config from key-value system settings
func LoadConfigFromSettings(s map[string]string) Config {
	port, _ := strconv.Atoi(s["ad_port"])
	if port <= 0 {
		port = 389
	}
	timeoutSec, _ := strconv.Atoi(s["ad_timeout_sec"])
	if timeoutSec <= 0 {
		timeoutSec = 10
	}

	return Config{
		Enabled:            s["ad_enabled"] == "true" || s["ad_enabled"] == "1",
		Server:             strings.TrimSpace(s["ad_server"]),
		Port:               port,
		UseSSL:             s["ad_use_ssl"] == "true" || s["ad_use_ssl"] == "1",
		StartTLS:           s["ad_start_tls"] == "true" || s["ad_start_tls"] == "1",
		InsecureSkipVerify: s["ad_insecure_skip_verify"] == "true" || s["ad_insecure_skip_verify"] == "1",
		BaseDN:             strings.TrimSpace(s["ad_base_dn"]),
		BindDN:             strings.TrimSpace(s["ad_bind_dn"]),
		BindPassword:       s["ad_bind_password"],
		UserFilter:         strings.TrimSpace(s["ad_user_filter"]),
		UsernameAttr:       strings.TrimSpace(s["ad_username_attr"]),
		NameAttr:           strings.TrimSpace(s["ad_name_attr"]),
		EmailAttr:          strings.TrimSpace(s["ad_email_attr"]),
		DefaultRole:        strings.TrimSpace(s["ad_default_role"]),
		Timeout:            time.Duration(timeoutSec) * time.Second,
	}
}

// dial establishes an LDAP or LDAPS connection according to configuration
func (c *Client) dial() (*ldap.Conn, error) {
	if c.cfg.Server == "" {
		return nil, fmt.Errorf("active directory server address is not configured")
	}

	address := fmt.Sprintf("%s:%d", c.cfg.Server, c.cfg.Port)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.cfg.InsecureSkipVerify,
		ServerName:         c.cfg.Server,
	}

	var conn *ldap.Conn
	var err error

	if c.cfg.UseSSL {
		conn, err = ldap.DialTLS("tcp", address, tlsConfig)
	} else {
		conn, err = ldap.Dial("tcp", address)
		if err == nil && c.cfg.StartTLS {
			err = conn.StartTLS(tlsConfig)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("connecting to AD server (%s): %w", address, err)
	}

	conn.SetTimeout(c.cfg.Timeout)
	return conn, nil
}

// TestConnection verifies network connectivity and service account credentials
func (c *Client) TestConnection() error {
	conn, err := c.dial()
	if err != nil {
		return err
	}
	defer conn.Close()

	if c.cfg.BindDN != "" {
		if err := conn.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
			return fmt.Errorf("service account bind failed for %s: %w", c.cfg.BindDN, err)
		}
	}
	return nil
}

// SearchUsers searches the directory for users matching the configured criteria
func (c *Client) SearchUsers(limit int) ([]User, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if c.cfg.BindDN != "" {
		if err := conn.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
			return nil, fmt.Errorf("ad bind authentication failed: %w", err)
		}
	}

	// Build search filter
	filter := c.cfg.UserFilter
	if filter == "" {
		filter = "(&(objectCategory=person)(objectClass=user))"
	}
	if !strings.HasPrefix(filter, "(") {
		filter = "(" + filter + ")"
	}

	if limit <= 0 {
		limit = 250
	}

	attributes := []string{
		c.cfg.UsernameAttr,
		c.cfg.NameAttr,
		c.cfg.EmailAttr,
		"userPrincipalName",
		"memberOf",
		"userAccountControl",
		"dn",
	}

	searchReq := ldap.NewSearchRequest(
		c.cfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		limit,
		int(c.cfg.Timeout.Seconds()),
		false,
		filter,
		attributes,
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("ad search failed: %w", err)
	}

	users := make([]User, 0, len(sr.Entries))
	for _, entry := range sr.Entries {
		username := entry.GetAttributeValue(c.cfg.UsernameAttr)
		if username == "" {
			username = entry.GetAttributeValue("userPrincipalName")
		}
		if username == "" {
			continue // Skip unnamed objects
		}

		fullName := entry.GetAttributeValue(c.cfg.NameAttr)
		if fullName == "" {
			fullName = username
		}

		email := entry.GetAttributeValue(c.cfg.EmailAttr)
		if email == "" {
			email = entry.GetAttributeValue("userPrincipalName")
		}

		// Check userAccountControl (UAC 2 = ACCOUNTDISABLE)
		uacVal := entry.GetAttributeValue("userAccountControl")
		isEnabled := true
		if uac, err := strconv.Atoi(uacVal); err == nil {
			if uac&2 != 0 {
				isEnabled = false
			}
		}

		users = append(users, User{
			Username:  username,
			FullName:  fullName,
			Email:     email,
			DN:        entry.DN,
			MemberOf:  entry.GetAttributeValues("memberOf"),
			Role:      c.cfg.DefaultRole,
			IsEnabled: isEnabled,
		})
	}

	return users, nil
}

// AuthenticateUser verifies a username and password against Active Directory.
// It can authenticate either by binding directly with user credentials, or
// by first searching the user's DN using the bind account and then binding as the user.
func (c *Client) AuthenticateUser(username, password string) (*User, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, fmt.Errorf("username and password required")
	}

	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	userDN := ""
	var userRecord *User

	// If service account is configured, find user DN and profile first
	if c.cfg.BindDN != "" {
		if err := conn.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
			return nil, fmt.Errorf("service account bind failed: %w", err)
		}

		escapedUser := ldap.EscapeFilter(username)
		filter := fmt.Sprintf("(&(objectCategory=person)(objectClass=user)(|(%s=%s)(userPrincipalName=%s)))",
			c.cfg.UsernameAttr, escapedUser, escapedUser)

		searchReq := ldap.NewSearchRequest(
			c.cfg.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			1,
			int(c.cfg.Timeout.Seconds()),
			false,
			filter,
			[]string{c.cfg.UsernameAttr, c.cfg.NameAttr, c.cfg.EmailAttr, "userPrincipalName", "memberOf", "userAccountControl"},
			nil,
		)

		sr, err := conn.Search(searchReq)
		if err != nil || len(sr.Entries) == 0 {
			return nil, fmt.Errorf("user %q not found in Active Directory", username)
		}

		entry := sr.Entries[0]
		userDN = entry.DN

		uacVal := entry.GetAttributeValue("userAccountControl")
		isEnabled := true
		if uac, err := strconv.Atoi(uacVal); err == nil && (uac&2 != 0) {
			isEnabled = false
		}

		userRecord = &User{
			Username:  username,
			FullName:  entry.GetAttributeValue(c.cfg.NameAttr),
			Email:     entry.GetAttributeValue(c.cfg.EmailAttr),
			DN:        userDN,
			MemberOf:  entry.GetAttributeValues("memberOf"),
			Role:      c.cfg.DefaultRole,
			IsEnabled: isEnabled,
		}
	} else {
		// Attempt direct bind with username as UPN or DN
		userDN = username
		userRecord = &User{
			Username:  username,
			FullName:  username,
			Role:      c.cfg.DefaultRole,
			IsEnabled: true,
		}
	}

	// Authenticate by binding as the user
	if err := conn.Bind(userDN, password); err != nil {
		return nil, fmt.Errorf("active directory authentication failed: invalid credentials")
	}

	if !userRecord.IsEnabled {
		return nil, fmt.Errorf("active directory account is disabled")
	}

	return userRecord, nil
}
