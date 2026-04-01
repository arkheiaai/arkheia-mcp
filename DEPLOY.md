# Arkheia Detection System Deployment Guide

## Prerequisites

- **Docker Desktop**: Version 4.x or higher
- **RAM**: Minimum 8GB available
- **Ports**: Port `8098` must be free and available on the host machine

## Quick Start

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
2. Configure your `.env` file:
   - Set `JWT_SECRET` to a 64-character random hex string.
   - Set `ARKHEIA_LICENSE_KEY` to your provided license key.
3. Start the services:
   ```bash
   docker compose up -d
   ```

## Surface Installation

To configure detection profiles, you need to provide the signed YAML configuration files:

1. Locate the `profiles/` volume mount on your host machine (as defined in your `docker-compose.yml`).
2. Copy the signed `.yaml` files into this directory.
3. The system will automatically detect and load the new profiles.

## Health URLs

You can verify the system is running correctly by checking the following endpoints:

- **Root Health**: `GET http://localhost:8098/`
- **Admin Health**: `GET http://localhost:8098/admin/health`

## Upgrade

To upgrade to the latest version of the Arkheia detection system:

```bash
docker compose pull
docker compose up -d
```

## Troubleshooting

### Logs
To view the system logs, run:
```bash
docker compose logs -f
```

### JWT Errors
If you are seeing authentication or JWT errors, verify that:
- The `JWT_SECRET` in your `.env` file is exactly 64 hexadecimal characters.
- The client making the request is using the correct secret to sign the token.

### Port Conflicts
If port `8098` is already in use, you will see an error during startup.
- Identify the conflicting process using `lsof -i :8098` (macOS/Linux) or `netstat -ano | findstr :8098` (Windows).
- Stop the conflicting process or map the container to a different port in your `docker-compose.yml`.
