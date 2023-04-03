package certauthz

import (
	"context"
	"fmt"
	"regexp"
	"net/http"
)

type Config struct {
	Regex string `json:"sanDnsPermitRegex,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		Regex: "",
	}
}

type CertAuthz struct {
	next     http.Handler
	regex    *regexp.Regexp
	name     string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	var compiled, err = regexp.Compile(config.Regex)
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
