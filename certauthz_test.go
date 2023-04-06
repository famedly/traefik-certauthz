package certauthz_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	// "fmt"

	"github.com/famedly/traefik_certauthz_plugin"
)

// Config failures
func TestConfigFailure1(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Domains = []string{
		"example.org",
	}
	cfg.Regex = "^example[.]org$"
	
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	
	_, err := certauthz.New(ctx, next, cfg, "certauthz")
	if err == nil {
		t.Error("Expected config failure (both domain and regex configured), but succeeded")
	}
}

func TestConfigFailure2(t *testing.T) {
	cfg := certauthz.CreateConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	
	_, err := certauthz.New(ctx, next, cfg, "certauthz")
	if err == nil {
		t.Error("Expected config failure (neither domain nor regex configured), but succeeded")
	}
}

// Domain successes
func TestCertauthzDomainsSuccess1(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Domains = []string{
		"example.org",
	}
	sans := []string{
		"example.org",
	}
	testValidConfig(t, cfg, sans, "200 OK")
}

func TestCertauthzDomainsSuccess2(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Domains = []string{
		"example.org",
		"example.com",
	}
	sans := []string{
		"example.org",
	}
	testValidConfig(t, cfg, sans, "200 OK")
}

func TestCertauthzDomainsSuccess3(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Domains = []string{
		"example.org",
	}
	sans := []string{
		"example.org",
		"example.com",
	}
	testValidConfig(t, cfg, sans, "200 OK")
}

func TestCertauthzDomainsSuccess4(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Domains = []string{
		"eXamp1e.org",
		"example.net",
	}
	sans := []string{
		"examp1e.org",
		"example.edu",
	}
	testValidConfig(t, cfg, sans, "200 OK")
}

// TODO: implement wildcard SANs with proper checks for bad input
// func TestCertauthzDomainsSuccess5(t *testing.T) {
// 	cfg := certauthz.CreateConfig()
// 	cfg.Domains = []string{
// 		"sub.example.org",
// 	}
// 	sans := []string{
// 		"*.example.org",
// 	}
// 	testValidConfig(t, cfg, sans, "200 OK")
// }

// Domain failures
func TestCertauthzDomainsFailure1(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Domains = []string{
		"example.org",
	}
	
	testValidConfig(t, cfg, nil, "403 Forbidden")
}

func TestCertauthzDomainsFailure2(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Domains = []string{
		"example.org",
	}
	sans := []string{
		"example.com",
	}
	testValidConfig(t, cfg, sans, "403 Forbidden")
}

func TestCertauthzDomainsFailure3(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Domains = []string{
		"example.org",
		"example.net",
	}
	sans := []string{
		"example.com",
	}
	testValidConfig(t, cfg, sans, "403 Forbidden")
}

func TestCertauthzDomainsFailure4(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Domains = []string{
		"example.org",
		"example.net",
	}
	sans := []string{
		"example.com",
		"example.edu",
	}
	testValidConfig(t, cfg, sans, "403 Forbidden")
}

func TestCertauthzDomainsFailure5(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Domains = []string{
		"example.org",
	}
	sans := []string{
		"example.org.badactor.com",
		"sub.example.org.badactor.com",
	}
	testValidConfig(t, cfg, sans, "403 Forbidden")
}

func TestCertauthzDomainsFailure6(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Domains = []string{
		"example.org",
	}
	sans := []string{
		"examplexorg.badactor.com",
		"sub.examplexorg.badactor.com",
	}
	testValidConfig(t, cfg, sans, "403 Forbidden")
}

// Wildcard domain successes
func TestCertauthzWildcardDomainsSuccess1(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Domains = []string{
		"*.example.org",
	}
	sans := []string{
		"*.example.org",
	}
	testValidConfig(t, cfg, sans, "200 OK")
}

func TestCertauthzWildcardDomainsSuccess2(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Domains = []string{
		"*.example.org",
	}
	sans := []string{
		"example.org",
		"*.example.org",
	}
	testValidConfig(t, cfg, sans, "200 OK")
}

func TestCertauthzWildcardDomainsSuccess3(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Domains = []string{
		"*.example.org",
		"example.com",
	}
	sans := []string{
		"example.org",
		"*.example.org",
	}
	testValidConfig(t, cfg, sans, "200 OK")
}

func TestCertauthzWildcardDomainsSuccess4(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Domains = []string{
		"*.example.org",
		"example.com",
	}
	sans := []string{
		"sub.example.org",
	}
	testValidConfig(t, cfg, sans, "200 OK")
}

func TestCertauthzWildcardDomainsSuccess5(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Domains = []string{
		"example.*",
	}
	sans := []string{
		"example.org",
	}
	testValidConfig(t, cfg, sans, "200 OK")
}

func TestCertauthzWildcardDomainsSuccess6(t *testing.T) {
	cfg := certauthz.CreateConfig()
	// TODO: don't allow this, change test and document breaking change
	// require * to be followed by .
	cfg.Domains = []string{
		"exam*ple.org",
	}
	sans := []string{
		"examqwerple.org",
	}
	testValidConfig(t, cfg, sans, "200 OK")
}

func TestCertauthzWildcardDomainsSuccess7(t *testing.T) {
	cfg := certauthz.CreateConfig()
	// TODO: don't allow this, change test and document breaking change
	// require * to be followed by .
	cfg.Domains = []string{
		"*example.org",
	}
	sans := []string{
		"badactorexample.org",
	}
	testValidConfig(t, cfg, sans, "200 OK")
}

// Wildcard domain failures
func TestCertauthzWildcardDomainsFailure1(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Domains = []string{
		"*.example.org",
	}
	sans := []string{
		"example.org",
	}
	testValidConfig(t, cfg, sans, "403 Forbidden")
}

func TestCertauthzWildcardDomainsFailure2(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Domains = []string{
		"*.example.org",
	}
	sans := []string{
		"sub.example.com",
	}
	testValidConfig(t, cfg, sans, "403 Forbidden")
}

func TestCertauthzWildcardDomainsFailure3(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Domains = []string{
		"*.example.org",
	}
	sans := []string{
		"sub.sub.example.org",
	}
	testValidConfig(t, cfg, sans, "403 Forbidden")
}

func TestCertauthzWildcardDomainsFailure4(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Domains = []string{
		"*.example.org",
	}
	sans := []string{
		"*.example.com",
	}
	testValidConfig(t, cfg, sans, "403 Forbidden")
}

func TestCertauthzWildcardDomainsFailure5(t *testing.T) {
	cfg := certauthz.CreateConfig()
	// TODO: don't allow this, change test and document breaking change
	// require * to be followed by .
	cfg.Domains = []string{
		"exam*ple.org",
	}
	sans := []string{
		"example.org",
	}
	testValidConfig(t, cfg, sans, "403 Forbidden")
}

// Regex successes
func TestCertauthzRegexSuccess1(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Regex = "^example[.]org$"
	sans := []string{
		"example.org",
	}
	testValidConfig(t, cfg, sans, "200 OK")
}

func TestCertauthzRegexSuccess2(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Regex = "^example[.]org$|^[^.]+.example.org$"
	sans := []string{
		"sub.example.org",
	}
	testValidConfig(t, cfg, sans, "200 OK")
}

func TestCertauthzRegexSuccess3(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Regex = "^example[.]org$|^[^.]+.example.org$"
	sans := []string{
		"example.org",
		"sub.example.com",
	}
	testValidConfig(t, cfg, sans, "200 OK")
}

func TestCertauthzRegexSuccess4(t *testing.T) {
	cfg := certauthz.CreateConfig()
	// TODO: add a warning for not enclosing in ^$, change test to expect it
	cfg.Regex = "example.org"
	sans := []string{
		"example.org.badactor.com",
	}
	testValidConfig(t, cfg, sans, "200 OK")
}

func TestCertauthzRegexSuccess5(t *testing.T) {
	cfg := certauthz.CreateConfig()
	// TODO: add a warning for not enclosing in ^$, change test to expect it
	cfg.Regex = "example.org"
	sans := []string{
		"examplexorg.badactor.com",
	}
	testValidConfig(t, cfg, sans, "200 OK")
}

func TestCertauthzRegexSuccess6(t *testing.T) {
	cfg := certauthz.CreateConfig()
	// TODO: add a warning for not enclosing in ^$, change test to expect it
	cfg.Regex = "example.org"
	sans := []string{
		"examplexorg",
	}
	testValidConfig(t, cfg, sans, "200 OK")
}

// Regex failures
func TestCertauthzRegexFailure1(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Regex = "^example[.]org$"
	sans := []string{
		"examplexorg",
	}
	testValidConfig(t, cfg, sans, "403 Forbidden")
}

func TestCertauthzRegexFailure2(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Regex = "^example[.]org$"
	sans := []string{
		"example.org.badactor.com",
	}
	testValidConfig(t, cfg, sans, "403 Forbidden")
}

func TestCertauthzRegexFailure3(t *testing.T) {
	cfg := certauthz.CreateConfig()
	cfg.Regex = "^example[.]org$"
	sans := []string{
		"example.org.badactor.com",
	}
	testValidConfig(t, cfg, sans, "403 Forbidden")
}


func testValidConfig(t *testing.T, cfg *certauthz.Config, sans []string, expected string) {
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	
	handler, err := certauthz.New(ctx, next, cfg, "certauthz")
	if err != nil {
		t.Fatal(err)
	}
	
	recorder := httptest.NewRecorder()
	
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	
	if sans != nil {
		cert := createCertificate(sans)
		req.TLS = createTLSConnectionState(cert)
	}
	
	handler.ServeHTTP(recorder, req)
	res := recorder.Result()
	
	// fmt.Println(res)
	
	if res.Status != expected {
		t.Errorf("Expected Status '%s', got '%s'", expected, res.Status)
	}
}

func createTLSConnectionState(cert *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState {
		PeerCertificates: []*x509.Certificate{cert},
	}
}

func createCertificate(sans []string) *x509.Certificate {
	return &x509.Certificate {
		DNSNames: sans,
	}
}
