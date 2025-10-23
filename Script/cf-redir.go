package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	RedirectHost   string `json:"redirect_host"`
	DirectHost     string `json:"direct_host"`
	AuthEmail      string `json:"auth_email"`
	AuthKey        string `json:"auth_key"`
	RedirectToHTTPS bool  `json:"redirect_to_https"`
}

type CloudFlareRedir struct {
	AuthEmail string
	AuthKey   string
	Client    *http.Client
}

type DNSRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content,omitempty"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl"`
}

type Ruleset struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Phase       string `json:"phase"`
	Description string `json:"description,omitempty"`
	Rules       []Rule `json:"rules,omitempty"`
}

type Rule struct {
	ID               string           `json:"id,omitempty"`
	Action           string           `json:"action"`
	ActionParameters *ActionParameters `json:"action_parameters"`
	Description      string           `json:"description"`
	Enabled          bool             `json:"enabled"`
	Expression       string           `json:"expression"`
}

type ActionParameters struct {
	FromValue *FromValue `json:"from_value"`
}

type FromValue struct {
	StatusCode          int        `json:"status_code"`
	TargetURL           *TargetURL `json:"target_url"`
	PreserveQueryString bool       `json:"preserve_query_string"`
}

type TargetURL struct {
	Expression string `json:"expression"`
}

type CloudFlareResponse struct {
	Success bool            `json:"success"`
	Errors  []Error         `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type DNSRecordResponse struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
}

type RulesetResponse struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Phase string `json:"phase"`
	Rules []Rule `json:"rules,omitempty"`
}

func main() {
	if len(os.Args) != 6 {
		log.Fatal("Usage: cf-redir <protocol> <private_ip> <private_port> <public_ip> <public_port>")
	}

	_, _, _, publicIP, publicPort := os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5]

	config, err := loadConfig()
	if err != nil {
		log.Fatal("Error loading config: ", err)
	}

	cf := NewCloudFlareRedir(config.AuthEmail, config.AuthKey)

	fmt.Printf("Setting [ %s ] DNS to [ %s ] proxied by CloudFlare...\n", config.RedirectHost, publicIP)
	if err := cf.SetARecord(config.RedirectHost, publicIP, true); err != nil {
		log.Fatal("Error setting redirect host A record: ", err)
	}

	fmt.Printf("Setting [ %s ] DNS to [ %s ] directly...\n", config.DirectHost, publicIP)
	if err := cf.SetARecord(config.DirectHost, publicIP, false); err != nil {
		log.Fatal("Error setting direct host A record: ", err)
	}

	fmt.Printf("Setting [ %s ] redirecting to [ %s:%s ], https=%t...\n",
		config.RedirectHost, config.DirectHost, publicPort, config.RedirectToHTTPS)
	if err := cf.SetRedirectRule(config.RedirectHost, config.DirectHost, publicPort, config.RedirectToHTTPS); err != nil {
		log.Fatal("Error setting redirect rule: ", err)
	}

	fmt.Println("CloudFlare redirect configuration completed successfully!")
}

func loadConfig() (*Config, error) {
	configPaths := []string{
		"cloudflare.json",
		filepath.Join(os.Getenv("HOME"), ".config", "cloudflare.json"),
		"/etc/cloudflare.json",
	}

	for _, path := range configPaths {
		if data, err := ioutil.ReadFile(path); err == nil {
			var config Config
			if err := json.Unmarshal(data, &config); err == nil {
				return &config, nil
			} else {
				log.Printf("Error parsing config file %s: %v", path, err)
			}
		}
	}

	return nil, fmt.Errorf("Could not find cloudflare.json in any expected location: %v", configPaths)
}

func NewCloudFlareRedir(authEmail, authKey string) *CloudFlareRedir {
	rootCAs, err := x509.SystemCertPool()
	if err != nil || rootCAs == nil {
		log.Println("Warning: System cert pool not available, creating new one")
		rootCAs = x509.NewCertPool()

		certPaths := []string{
			"/etc/ssl/certs/ca-certificates.crt",
			"/etc/pki/tls/certs/ca-bundle.crt",
			"/etc/ssl/cert.pem",
		}

		for _, certPath := range certPaths {
			if data, err := ioutil.ReadFile(certPath); err == nil {
				if rootCAs.AppendCertsFromPEM(data) {
					log.Printf("Loaded certificates from %s", certPath)
					break
				}
			}
		}
	}

	return &CloudFlareRedir{
		AuthEmail: authEmail,
		AuthKey:   authKey,
		Client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: rootCAs,
				},
			},
		},
	}
}

func (cf *CloudFlareRedir) SetARecord(name, ipaddr string, proxied bool) error {
	zoneID, err := cf.findZoneID(name)
	if err != nil {
		return err
	}

	recordID, err := cf.findARecord(zoneID, name)
	if err != nil {
		return err
	}

	if recordID == "" {
		return cf.createARecord(zoneID, name, ipaddr, proxied)
	}
	return cf.updateARecord(zoneID, recordID, name, ipaddr, proxied)
}

func (cf *CloudFlareRedir) SetRedirectRule(redirectHost, directHost, publicPort string, https bool) error {
	zoneID, err := cf.findZoneID(redirectHost)
	if err != nil {
		return err
	}

	rulesetID, err := cf.getRedirRuleset(zoneID)
	if err != nil {
		return err
	}

	if rulesetID == "" {
		rulesetID, err = cf.createRedirRuleset(zoneID)
		if err != nil {
			return err
		}
	}

	ruleID, err := cf.findRedirRule(zoneID, rulesetID, redirectHost)
	if err != nil {
		return err
	}

	if ruleID == "" {
		return cf.createRedirRule(zoneID, rulesetID, redirectHost, directHost, publicPort, https)
	}
	return cf.updateRedirRule(zoneID, rulesetID, ruleID, redirectHost, directHost, publicPort, https)
}

func (cf *CloudFlareRedir) apiRequest(method, url string, data interface{}) (*CloudFlareResponse, error) {
	var reqBody []byte
	var err error

	if data != nil {
		reqBody, err = json.Marshal(data)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Auth-Email", cf.AuthEmail)
	req.Header.Set("X-Auth-Key", cf.AuthKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := cf.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result CloudFlareResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if !result.Success {
		errorMsg := "CloudFlare API error"
		if len(result.Errors) > 0 {
			errorMsg = fmt.Sprintf("%s: %v", errorMsg, result.Errors)
		}
		return nil, fmt.Errorf(errorMsg)
	}

	return &result, nil
}

func (cf *CloudFlareRedir) findZoneID(name string) (string, error) {
	result, err := cf.apiRequest("GET", "https://api.cloudflare.com/client/v4/zones", nil)
	if err != nil {
		return "", err
	}

	var zones []Zone
	if err := json.Unmarshal(result.Result, &zones); err != nil {
		return "", fmt.Errorf("Failed to parse zones response: %v", err)
	}

	name = strings.ToLower(name)
	for _, zone := range zones {
		if name == zone.Name || strings.HasSuffix(name, "."+zone.Name) {
			return zone.ID, nil
		}
	}

	return "", fmt.Errorf("%s is not on CloudFlare", name)
}

func (cf *CloudFlareRedir) findARecord(zoneID, name string) (string, error) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID)
	result, err := cf.apiRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	var records []DNSRecordResponse
	if err := json.Unmarshal(result.Result, &records); err != nil {
		return "", fmt.Errorf("Failed to parse DNS records response: %v", err)
	}

	name = strings.ToLower(name)
	for _, record := range records {
		if record.Type == "A" && record.Name == name {
			return record.ID, nil
		}
	}

	return "", nil
}

func (cf *CloudFlareRedir) createARecord(zoneID, name, ipaddr string, proxied bool) error {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID)
	record := DNSRecord{
		Type:    "A",
		Name:    strings.ToLower(name),
		Content: ipaddr,
		Proxied: proxied,
		TTL:     120,
	}
	_, err := cf.apiRequest("POST", url, record)
	return err
}

func (cf *CloudFlareRedir) updateARecord(zoneID, recordID, name, ipaddr string, proxied bool) error {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneID, recordID)
	record := DNSRecord{
		Type:    "A",
		Name:    strings.ToLower(name),
		Content: ipaddr,
		Proxied: proxied,
		TTL:     120,
	}
	_, err := cf.apiRequest("PUT", url, record)
	return err
}

func (cf *CloudFlareRedir) getRedirRuleset(zoneID string) (string, error) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/rulesets", zoneID)
	result, err := cf.apiRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	var rulesets []RulesetResponse
	if err := json.Unmarshal(result.Result, &rulesets); err != nil {
		return "", fmt.Errorf("Failed to parse rulesets response: %v", err)
	}

	for _, ruleset := range rulesets {
		if ruleset.Phase == "http_request_dynamic_redirect" {
			return ruleset.ID, nil
		}
	}

	return "", nil
}

func (cf *CloudFlareRedir) createRedirRuleset(zoneID string) (string, error) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/rulesets", zoneID)
	ruleset := Ruleset{
		Name:  "Redirect rules ruleset",
		Kind:  "zone",
		Phase: "http_request_dynamic_redirect",
		Rules: []Rule{},
	}
	result, err := cf.apiRequest("POST", url, ruleset)
	if err != nil {
		return "", err
	}

	var createdRuleset RulesetResponse
	if err := json.Unmarshal(result.Result, &createdRuleset); err != nil {
		return "", fmt.Errorf("Failed to parse created ruleset response: %v", err)
	}

	return createdRuleset.ID, nil
}

func (cf *CloudFlareRedir) getDescription(redirectHost string) string {
	return fmt.Sprintf("Natter: %s", redirectHost)
}

func (cf *CloudFlareRedir) findRedirRule(zoneID, rulesetID, redirectHost string) (string, error) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/rulesets/%s", zoneID, rulesetID)
	result, err := cf.apiRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	var ruleset RulesetResponse
	if err := json.Unmarshal(result.Result, &ruleset); err != nil {
		return "", fmt.Errorf("Failed to parse ruleset response: %v", err)
	}

	description := cf.getDescription(redirectHost)
	for _, rule := range ruleset.Rules {
		if rule.Description == description {
			return rule.ID, nil
		}
	}

	return "", nil
}

func (cf *CloudFlareRedir) createRedirRule(zoneID, rulesetID, redirectHost, directHost, publicPort string, https bool) error {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/rulesets/%s/rules", zoneID, rulesetID)

	proto := "http"
	if https {
		proto = "https"
	}

	portInt, err := strconv.Atoi(publicPort)
	if err != nil {
		return fmt.Errorf("Invalid port number: %v", err)
	}

	rule := Rule{
		Action: "redirect",
		ActionParameters: &ActionParameters{
			FromValue: &FromValue{
				StatusCode: 302,
				TargetURL: &TargetURL{
					Expression: fmt.Sprintf(`concat("%s://%s:%d", http.request.uri.path)`, proto, directHost, portInt),
				},
				PreserveQueryString: true,
			},
		},
		Description: cf.getDescription(redirectHost),
		Enabled:     true,
		Expression:  fmt.Sprintf(`(http.host eq "%s")`, redirectHost),
	}

	_, err = cf.apiRequest("POST", url, rule)
	return err
}

func (cf *CloudFlareRedir) updateRedirRule(zoneID, rulesetID, ruleID, redirectHost, directHost, publicPort string, https bool) error {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/rulesets/%s/rules/%s", zoneID, rulesetID, ruleID)

	proto := "http"
	if https {
		proto = "https"
	}

	portInt, err := strconv.Atoi(publicPort)
	if err != nil {
		return fmt.Errorf("Invalid port number: %v", err)
	}

	rule := Rule{
		Action: "redirect",
		ActionParameters: &ActionParameters{
			FromValue: &FromValue{
				StatusCode: 302,
				TargetURL: &TargetURL{
					Expression: fmt.Sprintf(`concat("%s://%s:%d", http.request.uri.path)`, proto, directHost, portInt),
				},
				PreserveQueryString: true,
			},
		},
		Description: cf.getDescription(redirectHost),
		Enabled:     true,
		Expression:  fmt.Sprintf(`(http.host eq "%s")`, redirectHost),
	}

	_, err = cf.apiRequest("PATCH", url, rule)
	return err
}
