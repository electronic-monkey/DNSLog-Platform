# Security Policy

- Do not file public issues for sensitive vulnerabilities. Email the maintainers instead.
- Always rotate your SECRET_KEY, ADMIN_PASSWORD, and API tokens for production.
- Restrict access to /settings to administrators only (default behavior).
- Run behind HTTPS and a reverse proxy when exposed to the internet.
- Open only required ports (8000/tcp, 53/udp) and rate-limit DNS if Internet-facing.

## Reporting a Vulnerability

Please email: security@example.com with details and steps to reproduce. We will acknowledge receipt within 72 hours.

## Hardening Checklist
- Set environment variables: SECRET_KEY, ADMIN_PASSWORD, DOMAIN.
- Place the app behind a WAF/reverse proxy (TLS termination).
- Configure firewalls and OS updates regularly.
- Enable log rotation (see run/logrotate.dnslog).
- Monitor Prometheus metrics and set alerts on spikes.
