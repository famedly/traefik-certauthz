# Client Certificate Authorization Plugin for traefik

This plugin authorizes requests based on the SAN DNS names of a TLS client certificate.
If the client does not present a certificate or does present a certificate which according to
configuration is not allowed to continue, `403 Forbidden` is returned.

**CAUTION:**
This plugin does not validate the certificate it receives.
Please use the [traefik mTLS configuration](https://doc.traefik.io/traefik/https/tls/#client-authentication-mtls)
to also validate the certificate against a CA that you specify.

## Configuration

### Static configuration
```yaml
experimental:
  plugins:
    certauthz:
      moduleName: "github.com/famedly/traefik-certauthz"
      version: "v0.1.0"
```

### Dynamic configuration
```yaml
http:
  middlewares:
    my-certauthz:
      plugin:
        certauthz:
          domains:
            - "example.org"
            - "*.example.net"

  routers:
    my-router:
      middlewares:
        - "my-certauthz"
      tls:
        # Traefik mtls configuration is required for certificate validation
        # https://doc.traefik.io/traefik/https/tls/#client-authentication-mtls
        options: my-mtls
      entrypoints: […]
      rule: …
      service: …

tls:
  options:
    my-mtls:
      clientAuth:
        caFiles:
          - /etc/ssl/certs/ca-certificates.crt
        clientAuthType: RequireAndVerifyClientCert
```

#### Regex
Instead of providing a list of domains you can also specify a regex to match against.
**This is not recommended.**

```yaml
http:
  middlewares:
    my-certauthz:
      plugin:
        certauthz:
          regex: "^example\.org$"
```

If you forget to use `^` and `$` an attacker would be able to pass with
a certificate with SAN `DNS:example.org.badactor.com`.
The `.` character should also be escaped.
