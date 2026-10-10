package https

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/syslog-platform/logger/internal/database/postgres"
)

const (
	SettingHTTPSEnabled        = "https_enabled"
	SettingHTTPSPort           = "https_port"
	SettingHTTPSRedirect       = "https_redirect"
	SettingHTTPSCertPEM        = "https_cert_pem"
	SettingHTTPSKeyPEM         = "https_key_pem"
	SettingFQDNEnabled         = "fqdn_enabled"
	SettingFQDNHost            = "fqdn_host"
	SettingFQDNEnforce         = "fqdn_enforce_host"
	SettingFQDNRedirect        = "fqdn_redirect_to_fqdn"
	DefaultHTTPSPort           = 8443
)

// CertMetadata contains human-readable properties of the active SSL/TLS certificate
type CertMetadata struct {
	Subject           string    `json:"subject"`
	CommonName        string    `json:"common_name"`
	SubjectCN         string    `json:"subject_cn"`
	Issuer            string    `json:"issuer"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	DaysRemaining     int       `json:"days_remaining"`
	DNSNames          []string  `json:"dns_names"`
	IPAddresses       []string  `json:"ip_addresses"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	IsSelfSigned      bool      `json:"is_self_signed"`
	IsExpired         bool      `json:"is_expired"`
	KeyAlgorithm      string    `json:"key_algorithm"`
	KeyBits           int       `json:"key_bits"`
	KeyType           string    `json:"key_type"`
}

// HTTPSStatus represents the full TLS and FQDN configuration state
type HTTPSStatus struct {
	Enabled          bool          `json:"enabled"`
	Port             int           `json:"port"`
	RedirectHTTP     bool          `json:"redirect_http"`
	FQDNEnabled      bool          `json:"fqdn_enabled"`
	FQDNHost         string        `json:"fqdn_host"`
	FQDNEnforce      bool          `json:"fqdn_enforce"`
	FQDNRedirect     bool          `json:"fqdn_redirect"`
	ActiveCert       *CertMetadata `json:"active_cert,omitempty"`
	Certificate      *CertMetadata `json:"certificate,omitempty"`
	HasCertificate   bool          `json:"has_certificate"`
	ListeningAddress string        `json:"listening_address"`
	WebURL           string        `json:"web_url"`
}

// Manager controls the HTTPS lifecycle, certificate hot-reloading, and FQDN governance
type Manager struct {
	mu          sync.Mutex
	pgDB        *postgres.DB
	currentCert atomic.Pointer[tls.Certificate]
	currentMeta atomic.Pointer[CertMetadata]

	server   *http.Server
	listener net.Listener
	running  atomic.Bool

	handler http.Handler
	port    int
	enabled bool
}

// NewManager initializes the HTTPS manager
func NewManager(db *postgres.DB) *Manager {
	return &Manager{
		pgDB: db,
		port: DefaultHTTPSPort,
	}
}

// HasCertificate returns true if a valid TLS certificate is currently active in memory
func (m *Manager) HasCertificate() bool {
	return m.currentCert.Load() != nil
}

// Initialize loads stored TLS settings and certificate from PostgreSQL, or auto-generates on first enable
func (m *Manager) Initialize(ctx context.Context, handler http.Handler) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.handler = handler
	settings, err := m.pgDB.GetSettings(ctx)
	if err != nil {
		log.Printf("[HTTPS] Warning: could not load settings from DB: %v", err)
		settings = make(map[string]string)
	}

	m.enabled = settings[SettingHTTPSEnabled] == "true"
	if p, err := strconv.Atoi(settings[SettingHTTPSPort]); err == nil && p > 0 {
		m.port = p
	}

	certPEM := settings[SettingHTTPSCertPEM]
	keyPEM := settings[SettingHTTPSKeyPEM]

	if certPEM != "" && keyPEM != "" {
		if cert, meta, err := parseKeyPair([]byte(certPEM), []byte(keyPEM)); err == nil {
			m.currentCert.Store(cert)
			m.currentMeta.Store(meta)
			log.Printf("[HTTPS] Active certificate loaded: CN=%s, Expires=%s (Remaining: %d days)",
				meta.CommonName, meta.NotAfter.Format("2006-01-02"), meta.DaysRemaining)
		} else {
			log.Printf("[HTTPS] Stored certificate invalid: %v", err)
		}
	} else if m.enabled {
		// Enabled but certificate missing: auto-generate default self-signed cert
		fqdn := settings[SettingFQDNHost]
		if fqdn == "" {
			fqdn = "localhost"
		}
		log.Printf("[HTTPS] Auto-generating initial self-signed certificate for CN=%s...", fqdn)
		_, _, _, genErr := m.generateSelfSignedLocked(ctx, fqdn, nil, 365, "Valtrivo LogSeal Authority")
		if genErr != nil {
			log.Printf("[HTTPS] Failed to auto-generate initial certificate: %v", genErr)
		}
	}

	return nil
}

// Start launches the HTTPS server in the background if enabled
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.enabled {
		log.Printf("[HTTPS] Secure web server is disabled in settings (HTTP only on default port)")
		return nil
	}

	if m.currentCert.Load() == nil {
		return errors.New("cannot start HTTPS server: no TLS certificate configured")
	}

	if m.running.Load() {
		return nil
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert := m.currentCert.Load()
			if cert == nil {
				return nil, errors.New("no certificate available")
			}
			return cert, nil
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	addr := fmt.Sprintf("0.0.0.0:%d", m.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("bind HTTPS socket on %s: %w", addr, err)
	}

	m.listener = tls.NewListener(ln, tlsConfig)
	m.server = &http.Server{
		Addr:         addr,
		Handler:      m.handler,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 0, // Streaming support
		TLSConfig:    tlsConfig,
	}

	m.running.Store(true)
	go func() {
		log.Printf("[HTTPS] Secure web dashboard & REST API listening on https://%s", addr)
		if err := m.server.Serve(m.listener); err != nil && err != http.ErrServerClosed {
			log.Printf("[HTTPS] Server stopped with error: %v", err)
			m.running.Store(false)
		}
	}()

	return nil
}

// Stop safely terminates the HTTPS server
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running.Load() || m.server == nil {
		return nil
	}

	m.running.Store(false)
	err := m.server.Shutdown(ctx)
	m.server = nil
	m.listener = nil
	return err
}

// GenerateSelfSigned creates an X.509 v3 self-signed certificate and hot-swaps it into memory
func (m *Manager) GenerateSelfSigned(ctx context.Context, commonName string, sans []string, validityDays int, organization string) (string, string, *CertMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.generateSelfSignedLocked(ctx, commonName, sans, validityDays, organization)
}

func (m *Manager) generateSelfSignedLocked(ctx context.Context, commonName string, sans []string, validityDays int, organization string) (string, string, *CertMetadata, error) {
	if commonName == "" {
		commonName = "localhost"
	}
	if validityDays <= 0 {
		validityDays = 365
	}
	if organization == "" {
		organization = "Valtrivo LogSeal Security"
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", nil, fmt.Errorf("generate RSA key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return "", "", nil, fmt.Errorf("generate serial: %w", err)
	}

	notBefore := time.Now().Add(-5 * time.Minute) // clock skew safety
	notAfter := notBefore.Add(time.Duration(validityDays) * 24 * time.Hour)

	dnsNames := []string{"localhost", commonName}
	ipAddresses := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}

	// Auto-discover machine IP addresses
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if addrs, err := iface.Addrs(); err == nil {
				for _, a := range addrs {
					var ip net.IP
					switch v := a.(type) {
					case *net.IPNet:
						ip = v.IP
					case *net.IPAddr:
						ip = v.IP
					}
					if ip != nil && !ip.IsLoopback() {
						ipAddresses = append(ipAddresses, ip)
					}
				}
			}
		}
	}

	// Add user-specified SANs
	for _, san := range sans {
		san = strings.TrimSpace(san)
		if san == "" {
			continue
		}
		if ip := net.ParseIP(san); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		} else {
			dnsNames = append(dnsNames, san)
		}
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{organization},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              uniqueStrings(dnsNames),
		IPAddresses:           uniqueIPs(ipAddresses),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return "", "", nil, fmt.Errorf("create certificate DER: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return "", "", nil, fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	cert, meta, err := parseKeyPair(certPEM, keyPEM)
	if err != nil {
		return "", "", nil, fmt.Errorf("verify generated keypair: %w", err)
	}

	// Persist to database
	_ = m.pgDB.SaveSetting(ctx, SettingHTTPSCertPEM, string(certPEM))
	_ = m.pgDB.SaveSetting(ctx, SettingHTTPSKeyPEM, string(keyPEM))

	// Hot-swap certificate
	m.currentCert.Store(cert)
	m.currentMeta.Store(meta)

	log.Printf("[HTTPS] New self-signed certificate activated: CN=%s, Valid=%d days, Fingerprint=%s",
		meta.CommonName, validityDays, meta.FingerprintSHA256[:16]+"…")

	return string(certPEM), string(keyPEM), meta, nil
}

// UploadCertificate parses and activates an uploaded custom certificate and private key
func (m *Manager) UploadCertificate(ctx context.Context, certBytes, keyBytes []byte) (*CertMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cert, meta, err := parseKeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, fmt.Errorf("validate certificate/key pair: %w", err)
	}

	// Persist to database
	_ = m.pgDB.SaveSetting(ctx, SettingHTTPSCertPEM, string(certBytes))
	_ = m.pgDB.SaveSetting(ctx, SettingHTTPSKeyPEM, string(keyBytes))

	// Hot-swap certificate
	m.currentCert.Store(cert)
	m.currentMeta.Store(meta)

	log.Printf("[HTTPS] Custom certificate uploaded and hot-swapped: CN=%s, Issuer=%s, Expires=%s",
		meta.CommonName, meta.Issuer, meta.NotAfter.Format("2006-01-02"))

	return meta, nil
}

// ToggleHTTPS enables or disables the HTTPS listener and updates database
func (m *Manager) ToggleHTTPS(ctx context.Context, enabled bool, port int, redirect bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if port <= 0 {
		port = DefaultHTTPSPort
	}

	_ = m.pgDB.SaveSetting(ctx, SettingHTTPSEnabled, strconv.FormatBool(enabled))
	_ = m.pgDB.SaveSetting(ctx, SettingHTTPSPort, strconv.Itoa(port))
	_ = m.pgDB.SaveSetting(ctx, SettingHTTPSRedirect, strconv.FormatBool(redirect))

	m.enabled = enabled
	m.port = port

	if enabled {
		if m.currentCert.Load() == nil {
			// Auto-generate self-signed cert if missing
			_, _, _, _ = m.generateSelfSignedLocked(ctx, "localhost", nil, 365, "Valtrivo LogSeal")
		}
		// If running, restart on new port
		if m.running.Load() {
			_ = m.server.Shutdown(ctx)
			m.running.Store(false)
		}
		// Unlock temporarily to call Start
		m.mu.Unlock()
		err := m.Start()
		m.mu.Lock()
		return err
	}

	// If disabled, stop HTTPS server
	if m.running.Load() && m.server != nil {
		err := m.server.Shutdown(ctx)
		m.running.Store(false)
		return err
	}

	return nil
}

// GetCertificateDownload returns PEM certificate bytes for client download
func (m *Manager) GetCertificateDownload() ([]byte, string, error) {
	meta := m.currentMeta.Load()
	if meta == nil {
		return nil, "", errors.New("no certificate currently loaded")
	}

	settings, err := m.pgDB.GetSettings(context.Background())
	if err != nil || settings[SettingHTTPSCertPEM] == "" {
		return nil, "", errors.New("certificate data not found")
	}

	filename := "logseal-server.crt"
	if meta.CommonName != "" && meta.CommonName != "localhost" {
		filename = fmt.Sprintf("%s.crt", meta.CommonName)
	}

	return []byte(settings[SettingHTTPSCertPEM]), filename, nil
}

// GetStatus returns the current HTTPS, FQDN, and certificate operational status
func (m *Manager) GetStatus(ctx context.Context) HTTPSStatus {
	settings, _ := m.pgDB.GetSettings(ctx)

	enabled := settings[SettingHTTPSEnabled] == "true"
	port := DefaultHTTPSPort
	if p, err := strconv.Atoi(settings[SettingHTTPSPort]); err == nil && p > 0 {
		port = p
	}

	meta := m.currentMeta.Load()
	fqdnEnabled := settings[SettingFQDNEnabled] == "true"
	fqdnHost := settings[SettingFQDNHost]

	hostPart := "localhost"
	if fqdnEnabled && fqdnHost != "" {
		hostPart = fqdnHost
	}

	webURL := fmt.Sprintf("http://%s:8080", hostPart)
	if enabled {
		webURL = fmt.Sprintf("https://%s:%d", hostPart, port)
	}

	return HTTPSStatus{
		Enabled:          enabled,
		Port:             port,
		RedirectHTTP:     settings[SettingHTTPSRedirect] == "true",
		FQDNEnabled:      fqdnEnabled,
		FQDNHost:         fqdnHost,
		FQDNEnforce:      settings[SettingFQDNEnforce] == "true",
		FQDNRedirect:     settings[SettingFQDNRedirect] == "true",
		ActiveCert:       meta,
		Certificate:      meta,
		HasCertificate:   meta != nil,
		ListeningAddress: fmt.Sprintf("0.0.0.0:%d", port),
		WebURL:           webURL,
	}
}

// parseKeyPair parses, validates, and inspects an X.509 certificate and private key
func parseKeyPair(certPEM, keyPEM []byte) (*tls.Certificate, *CertMetadata, error) {
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, err
	}

	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("parse X.509 leaf: %w", err)
	}

	fp := sha256.Sum256(x509Cert.Raw)
	fpHex := strings.ToUpper(hex.EncodeToString(fp[:]))
	var fpFormatted []string
	for i := 0; i < len(fpHex); i += 2 {
		fpFormatted = append(fpFormatted, fpHex[i:i+2])
	}

	var ipStrings []string
	for _, ip := range x509Cert.IPAddresses {
		ipStrings = append(ipStrings, ip.String())
	}

	now := time.Now()
	daysRemaining := int(x509Cert.NotAfter.Sub(now).Hours() / 24)

	meta := &CertMetadata{
		Subject:           x509Cert.Subject.String(),
		CommonName:        x509Cert.Subject.CommonName,
		SubjectCN:         x509Cert.Subject.CommonName,
		Issuer:            x509Cert.Issuer.String(),
		NotBefore:         x509Cert.NotBefore,
		NotAfter:          x509Cert.NotAfter,
		DaysRemaining:     daysRemaining,
		DNSNames:          x509Cert.DNSNames,
		IPAddresses:       ipStrings,
		FingerprintSHA256: strings.Join(fpFormatted, ":"),
		IsSelfSigned:      x509Cert.Subject.String() == x509Cert.Issuer.String(),
		IsExpired:         now.After(x509Cert.NotAfter) || now.Before(x509Cert.NotBefore),
		KeyAlgorithm:      x509Cert.PublicKeyAlgorithm.String(),
	}

	if rsaKey, ok := x509Cert.PublicKey.(*rsa.PublicKey); ok {
		meta.KeyBits = rsaKey.N.BitLen()
	}
	if meta.KeyBits > 0 {
		meta.KeyType = fmt.Sprintf("%s %d-bit", meta.KeyAlgorithm, meta.KeyBits)
	} else {
		meta.KeyType = meta.KeyAlgorithm
	}

	return &tlsCert, meta, nil
}

func uniqueStrings(input []string) []string {
	u := make([]string, 0, len(input))
	m := make(map[string]bool)
	for _, val := range input {
		val = strings.ToLower(strings.TrimSpace(val))
		if val != "" && !m[val] {
			m[val] = true
			u = append(u, val)
		}
	}
	return u
}

func uniqueIPs(input []net.IP) []net.IP {
	u := make([]net.IP, 0, len(input))
	m := make(map[string]bool)
	for _, val := range input {
		if val == nil {
			continue
		}
		s := val.String()
		if !m[s] {
			m[s] = true
			u = append(u, val)
		}
	}
	return u
}
