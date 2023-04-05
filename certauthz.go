package certauthz

import (
	"context"
	"fmt"
	"regexp"
	"net/http"
	"strings"
)

type Config struct {
	Regex string
	Domains []string
}

func CreateConfig() *Config {
	return &Config{
		Regex: "",
		Domains: nil,
	}
}

type CertAuthz struct {
	next     http.Handler
	regex    *regexp.Regexp
	name     string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.Regex != "" && len(config.Domains) != 0 {
		return nil, fmt.Errorf("You must specify either a regex or a domain list, not both")
	}
	if config.Regex == "" && len(config.Domains) == 0 {
		return nil, fmt.Errorf("You must specify either a regex or a domain list")
	}

	var to_compile = config.Regex
	if len(config.Domains) > 0 {
		domains_regexes := []string{}
		for _, domain := range config.Domains {
			// Rudimentary check for invalid chars in domain
			// Invalid domain names are still possible
			var invalid = regexp.MustCompile(`(?i)[^a-z0-9\-\.\*]`)
			if invalid.MatchString(domain) {
				return nil, fmt.Errorf("Invalid characters in domain name: %v", domain)
			}
			domain = strings.Replace(domain, ".", "[.]", -1)
			domain = strings.Replace(domain, "*", "[^.]+", -1)
			domain = "(?i)^" + domain + "$"
			domains_regexes = append(domains_regexes, domain)
		}
		to_compile = strings.Join(domains_regexes, "|")
	}

	var compiled, err = regexp.Compile(to_compile)
	if err != nil {
		return nil, err
	}

	return &CertAuthz{
		regex:    compiled,
		next:     next,
		name:     name,
	}, nil
}

func (a *CertAuthz) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.TLS != nil && len(req.TLS.PeerCertificates) != 0 {
		var cert = req.TLS.PeerCertificates[0] // leaf certificate
		for _, name := range cert.DNSNames {
			if a.regex.MatchString(name) {
				a.next.ServeHTTP(rw, req)
				return
			}
		}
	}
	http.Error(rw, "No matching DNSNames", http.StatusForbidden)
	return
}
