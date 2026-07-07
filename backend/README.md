# Live HoneyPot Backend

Serverless backend for the Live HoneyPot telemetry platform.

The backend is implemented using **DigitalOcean Functions** and provides APIs for ingesting telemetry reports and serving them to frontend applications.

---

## Overview

The backend consists of two serverless functions:

| Function | Purpose |
|----------|---------|
| `/ingest` | Validates and stores telemetry reports |
| `/telemetry` | Serves cached telemetry reports |

Telemetry is stored in **Upstash Redis** and consumed by the Live HoneyPot website.

---

## Functions

### POST live-telemetry/ingest

Stores a telemetry report.

#### Request

```json
{
  "report_type": "latest",
  "data": {
    ...
  }
}
```

Supported report types:

| Value | Description |
|--------|-------------|
| `latest` | Most recent 24-hour telemetry snapshot |
| `daily` | Calendar-day report |

#### Behavior

- Validates request payload
- Validates security token
- Stores report in Upstash Redis
- Applies TTL for report types that require expiration
- Returns success or validation errors

---

### GET live-telemetry/telemetry

Retrieves a telemetry report.

#### Query Parameters

| Parameter | Required | Description |
|----------|----------|-------------|
| `host_id` | Yes | Honeypot identifier |
| `mode` | No | `latest` or `daily` (default: `latest`) |
| `date` | No | Daily report date (`YYYY-MM-DD`) |

Examples:

```
GET live-telemetry/telemetry?host_id=hp-do-sfo3
```

```
GET live-telemetry/telemetry?host_id=hp-do-sfo3&mode=daily&date=2026-07-05
```

---

## Environment Variables

Example:

```
UPSTASH_URL=
UPSTASH_TOKEN=
WEB_SECURE_TOKEN=
```

Create a local `.env` file for development.

Do **not** commit `.env`.

---

## Invoke Functions

### Invoke Remotely
```bash
doctl serverless functions invoke live-telemetry/telemetry -P .\test\telemetry-test-value.json

doctl serverless functions invoke live-telemetry/ingest -P .\test\ingest-test-value.json
```

### Invoke Locally

```bash
cd backend
node --env-file=.env ./test/test_telemetry.js
node --env-file=.env ./test/test_ingest.js
```

---

## Deployment

Deploy using the DigitalOcean Functions package structure:

```bash
cd backend
doctl serverless deploy .
```

Deployment configuration is defined in:

```
project.yml
```

---

## Security

The backend is designed so that:

- Elasticsearch is never exposed publicly.
- The frontend communicates only with `/telemetry`.
- `/ingest` requires a shared security token.
- Secrets are provided through environment variables.

---

## Future Improvements

- Historical report API
- Additional report types
- Rate limiting
- Authentication
- Health endpoint

---

## References
- https://docs.digitalocean.com/reference/doctl/
- https://docs.digitalocean.com/products/functions/