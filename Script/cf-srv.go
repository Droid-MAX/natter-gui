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
	Service   string `json:"service"`
	Domain    string `json:"domain"`
	AuthEmail string `json:"auth_email"`
	AuthKey   string `json:"auth_key"`
}

type CloudFlareDNS struct {
	AuthEmail string
	AuthKey   string
	Client    *http.Client
}

type DNSRecord struct {
	ID      string  `json:"id,omitempty"`
	Type    string  `json:"type"`
	Name    string  `json:"name"`
	Content string  `json:"content,omitempty"`
	Data    *SRVData `json:"data,omitempty"`
	Proxied bool    `json:"proxied"`
	TTL     int     `json:"ttl"`
}

type SRVData struct {
	Port     int    `json:"port"`
	Priority int    `json:"priority"`
	Target   string `json:"target"`
	Weight   int    `json:"weight"`
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
	ID     string `json:"id"`
	Type   string `json:"type"`
	Name   string `json:"name"`
	Data   *SRVData `json:"data,omitempty"`
}

func main() {
	if len(os.Args) != 6 {
		log.Fatal("Usage: cf-srv <protocol> <private_ip> <private_port> <public_ip> <public_port>")
	}

	protocol, _, _, publicIP, publicPort := os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5]

	config, err := loadConfig()
	if err != nil {
		log.Fatal("Error loading config: ", err)
	}

	cf := NewCloudFlareDNS(config.AuthEmail, config.AuthKey)

	fmt.Printf("Setting %s A record to %s...\n", config.Domain, publicIP)
	if err := cf.SetARecord(config.Domain, publicIP); err != nil {
		log.Fatal("Error setting A record: ", err)
	}

	fmt.Printf("Setting %s SRV record to %s port %s...\n", config.Domain, protocol, publicPort)
	if err := cf.SetSRVRecord(config.Domain, publicPort, config.Service, "_"+protocol); err != nil {
		log.Fatal("Error setting SRV record: ", err)
	}

	fmt.Println("DNS records updated successfully!")
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

func NewCloudFlareDNS(authEmail, authKey string) *CloudFlareDNS {
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

	return &CloudFlareDNS{
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

func (cf *CloudFlareDNS) SetARecord(name, ipaddr string) error {
	zoneID, err := cf.findZoneID(name)
	if err != nil {
		return err
	}

	recordID, err := cf.findARecord(zoneID, name)
	if err != nil {
		return err
	}

	if recordID == "" {
		return cf.createARecord(zoneID, name, ipaddr)
	}
	return cf.updateARecord(zoneID, recordID, name, ipaddr)
}

func (cf *CloudFlareDNS) SetSRVRecord(name, port, service, protocol string) error {
	zoneID, err := cf.findZoneID(name)
	if err != nil {
		return err
	}

	recordName := fmt.Sprintf("%s.%s.%s", service, protocol, name)
	recordID, err := cf.findSRVRecord(zoneID, recordName)
	if err != nil {
		return err
	}

	portInt, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("Invalid port number: %v", err)
	}

	if recordID == "" {
		return cf.createSRVRecord(zoneID, recordName, portInt, name)
	}
	return cf.updateSRVRecord(zoneID, recordID, recordName, portInt, name)
}

func (cf *CloudFlareDNS) apiRequest(method, url string, data interface{}) (*CloudFlareResponse, error) {
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

func (cf *CloudFlareDNS) findZoneID(name string) (string, error) {
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

func (cf *CloudFlareDNS) findARecord(zoneID, name string) (string, error) {
	return cf.findRecord(zoneID, "A", name)
}

func (cf *CloudFlareDNS) findSRVRecord(zoneID, name string) (string, error) {
	return cf.findRecord(zoneID, "SRV", name)
}

func (cf *CloudFlareDNS) findRecord(zoneID, recordType, name string) (string, error) {
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
		if record.Type == recordType && record.Name == name {
			return record.ID, nil
		}
	}

	return "", nil
}

func (cf *CloudFlareDNS) createARecord(zoneID, name, ipaddr string) error {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID)
	record := DNSRecord{
		Type:    "A",
		Name:    strings.ToLower(name),
		Content: ipaddr,
		Proxied: false,
		TTL:     120,
	}
	_, err := cf.apiRequest("POST", url, record)
	return err
}

func (cf *CloudFlareDNS) updateARecord(zoneID, recordID, name, ipaddr string) error {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneID, recordID)
	record := DNSRecord{
		Type:    "A",
		Name:    strings.ToLower(name),
		Content: ipaddr,
		Proxied: false,
		TTL:     120,
	}
	_, err := cf.apiRequest("PUT", url, record)
	return err
}

func (cf *CloudFlareDNS) createSRVRecord(zoneID, name string, port int, target string) error {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID)
	record := DNSRecord{
		Type: "SRV",
		Name: strings.ToLower(name),
		Data: &SRVData{
			Port:     port,
			Priority: 1,
			Target:   target,
			Weight:   10,
		},
		Proxied: false,
		TTL:     120,
	}
	_, err := cf.apiRequest("POST", url, record)
	return err
}

func (cf *CloudFlareDNS) updateSRVRecord(zoneID, recordID, name string, port int, target string) error {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneID, recordID)
	record := DNSRecord{
		Type: "SRV",
		Name: strings.ToLower(name),
		Data: &SRVData{
			Port:     port,
			Priority: 1,
			Target:   target,
			Weight:   10,
		},
		Proxied: false,
		TTL:     120,
	}
	_, err := cf.apiRequest("PUT", url, record)
	return err
}