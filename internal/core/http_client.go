package core

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"
)

type HTTPClient struct {
	client    *http.Client
	auth      AuthConfig
	userAgent string
}

func NewHTTPClient(timeout time.Duration, auth AuthConfig) *HTTPClient {
	jar, _ := cookiejar.New(nil)
	return &HTTPClient{
		client: &http.Client{
			Timeout: timeout,
			Jar:     jar,
		},
		auth:      auth,
		userAgent: "api-fuzzer/1.0",
	}
}

func (c *HTTPClient) Send(req *HTTPRequest, maxBodySize int64) (*HTTPResponse, error) {
	startTime := time.Now()

	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}

	httpReq, err := http.NewRequest(req.Method, req.URL, bodyReader)
	if err != nil {
		return &HTTPResponse{
			Error: err,
		}, err
	}

	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	if req.ContentType != "" {
		httpReq.Header.Set("Content-Type", req.ContentType)
	}

	for k, v := range req.Cookies {
		httpReq.AddCookie(&http.Cookie{Name: k, Value: v})
	}

	httpReq.Header.Set("User-Agent", c.userAgent)
	c.applyAuth(httpReq)

	resp, err := c.client.Do(httpReq)
	duration := time.Since(startTime)

	if err != nil {
		return &HTTPResponse{
			Duration: duration,
			Error:    err,
		}, err
	}
	defer resp.Body.Close()

	response := &HTTPResponse{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Headers:    make(map[string]string),
		Duration:   duration,
	}

	for k, v := range resp.Header {
		if len(v) > 0 {
			response.Headers[k] = v[0]
		}
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize+1))
	if err != nil {
		response.Error = err
		return response, err
	}

	if int64(len(bodyBytes)) > maxBodySize {
		response.Body = string(bodyBytes[:maxBodySize])
		response.BodyTruncated = true
	} else {
		response.Body = string(bodyBytes)
	}

	return response, nil
}

func (c *HTTPClient) applyAuth(req *http.Request) {
	switch c.auth.Type {
	case "bearer":
		if c.auth.BearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+c.auth.BearerToken)
		}
	case "apikey":
		switch c.auth.APIKeyIn {
		case "header":
			req.Header.Set(c.auth.APIKeyName, c.auth.APIKey)
		case "query":
			q := req.URL.Query()
			q.Set(c.auth.APIKeyName, c.auth.APIKey)
			req.URL.RawQuery = q.Encode()
		case "cookie":
			req.AddCookie(&http.Cookie{Name: c.auth.APIKeyName, Value: c.auth.APIKey})
		}
	case "basic":
		if c.auth.BasicAuthUser != "" {
			auth := c.auth.BasicAuthUser + ":" + c.auth.BasicAuthPass
			req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
		}
	}
}

func (c *HTTPClient) RefreshTokenIfNeeded(response *HTTPResponse) bool {
	if response.StatusCode == http.StatusUnauthorized && c.auth.OAuthClientID != "" {
		token, err := c.getOAuthToken()
		if err == nil && token != "" {
			c.auth.BearerToken = token
			return true
		}
	}
	return false
}

func (c *HTTPClient) getOAuthToken() (string, error) {
	if c.auth.OAuthTokenURL == "" || c.auth.OAuthClientID == "" {
		return "", fmt.Errorf("OAuth2 configuration incomplete")
	}

	data := map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     c.auth.OAuthClientID,
		"client_secret": c.auth.OAuthClientSecret,
	}
	if len(c.auth.OAuthScopes) > 0 {
		data["scope"] = strings.Join(c.auth.OAuthScopes, " ")
	}

	body, _ := json.Marshal(data)
	req, err := http.NewRequest("POST", c.auth.OAuthTokenURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)

	if token, ok := result["access_token"].(string); ok {
		return token, nil
	}
	return "", fmt.Errorf("failed to get token: %s", string(respBody))
}

func ToCurlCommand(req *HTTPRequest) string {
	var sb strings.Builder
	sb.WriteString("curl -X ")
	sb.WriteString(req.Method)
	sb.WriteString(" '")
	sb.WriteString(req.URL)
	sb.WriteString("'")

	for k, v := range req.Headers {
		sb.WriteString(" -H '")
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(v)
		sb.WriteString("'")
	}

	if req.ContentType != "" {
		sb.WriteString(" -H 'Content-Type: ")
		sb.WriteString(req.ContentType)
		sb.WriteString("'")
	}

	for k, v := range req.Cookies {
		sb.WriteString(" --cookie '")
		sb.WriteString(k)
		sb.WriteString("=")
		sb.WriteString(v)
		sb.WriteString("'")
	}

	if req.Body != "" {
		sb.WriteString(" -d '")
		sb.WriteString(strings.ReplaceAll(req.Body, "'", "'\\''"))
		sb.WriteString("'")
	}

	return sb.String()
}
