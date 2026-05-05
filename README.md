# Rust HTTPS Server

A production-ready HTTPS server with automatic TLS certificate provisioning and renewal via Let's Encrypt.

## Features

- **Automatic TLS** - Provisions certificates from Let's Encrypt using external ACME client (certbot)
- **Auto-renewal** - Certificates auto-renew before expiry with hot-swap (no downtime)
- **HTTP→HTTPS redirect** - Automatic redirect from port 80 to 443
- **ACME HTTP-01** - Built-in support for Let's Encrypt validation
- **Graceful shutdown** - Drain existing connections before stopping
- **Health endpoints** - `/health` and `/health/cert` for monitoring

## Quick Start

### Prerequisites

- Rust toolchain
- certbot (or other ACME client)
- OpenSSL
- Ports 80 and 443 open

### Build

```bash
cd http_server
cargo build --release
```

### Configure

Copy `.env.example` to `.env` and edit:

```bash
cp .env.example .env
nano .env
```

Required variables:
- `DOMAIN` - Your domain (e.g., example.com)
- `EMAIL` - Your email for Let's Encrypt

### Run

```bash
# Development
cargo run

# Production (needs ports 80 & 443)
sudo setcap 'cap_net_bind_service=+ep' target/release/http_server
./target/release/http_server
```

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `DOMAIN` | TLS certificate domain | (required) |
| `EMAIL` | Let's Encrypt contact | (required) |
| `CERT_DIR` | Certificate storage | `certs/` |
| `USE_STAGING` | Use Let's Encrypt staging | `true` |
| `HOST` | Server bind address | `0.0.0.0` |
| `PORT` | Server bind port | `443` |

## Deployment

### Systemd

1. Copy service file:
```bash
sudo cp http-server.service /etc/systemd/system/
```

2. Configure and start:
```bash
sudo cp .env.example /opt/http-server/.env
sudo nano /opt/http-server/.env
sudo systemctl daemon-reload
sudo systemctl enable http-server
sudo systemctl start http-server
```

## Health Endpoints

- `GET /health` - Basic health check
- `GET /health/cert` - Certificate status with days until expiry

## ACME Integration

Uses external ACME command. Default (certbot):
```bash
certbot certonly --webroot -w {cert_dir} -d {domain} --email {email} --agree-tos --non-interactive {staging_flag}
```

Customize via `ACME_CMD_TEMPLATE` env var.

## Development

```bash
# Format
cargo fmt

# Lint
cargo clippy -- -D warnings

# Test
cargo test

# Build
cargo build --release
```

## License

MIT