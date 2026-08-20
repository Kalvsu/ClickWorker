# ClickWorker local server

Express and MongoDB API with a static single-page frontend for the ClickWorker prototype.

## Prerequisites

- Node.js 18+
- A MongoDB database

## Setup

```bash
cp .env.example .env
# Set MONGODB_URI, a random 32+ character JWT_SECRET, and a strong ADMIN_PASSWORD in .env
pnpm install
pnpm start
```

The app is available at `http://localhost:3000` for local development. Production deployments must set `NODE_ENV=production` and an HTTPS `APP_BASE_URL`; terminate TLS at the hosting proxy and forward the original protocol.

> Do not commit `.env`; it contains local credentials.
