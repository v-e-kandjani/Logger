package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/syslog-platform/logger/agent/internal/version"
)

// Client handles secure HTTP/2 communication with the LOGGER server
type Client struct {
	baseURL    string
	authToken  string
	httpClient *http.Client
}

// NewClient initializes transport client
func NewClient(baseURL string, insecureTLS bool) *Client {
	baseURL = strings.TrimRight(baseURL, "/")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureTLS,
		},
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression: false,
	}

	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Transport: tr,
			Timeout:   20 * time.Second,
		},
	}
}

// SetAuthToken updates the active bearer authorization token
func (c *Client) SetAuthToken(token string) {
	c.authToken = token
}

// PostJSON sends an HTTP POST with JSON body and decodes JSON response
func (c *Client) PostJSON(ctx context.Context, endpoint string, reqData any, respData any) error {
	var bodyReader io.Reader
	if reqData != nil {
		data, err := json.Marshal(reqData)
		if err != nil {
			return fmt.Errorf("marshaling request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	url := c.baseURL + endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bodyReader)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", version.UserAgent())

	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(respBody))
	}

	if respData != nil {
		if err := json.NewDecoder(resp.Body).Decode(respData); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}

	return nil
}

// GetJSON performs an HTTP GET and decodes JSON response
func (c *Client) GetJSON(ctx context.Context, endpoint string, respData any) error {
	url := c.baseURL + endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", version.UserAgent())

	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(respBody))
	}

	if respData != nil {
		if err := json.NewDecoder(resp.Body).Decode(respData); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}

	return nil
}
