# ClickWorker local server

Express and MongoDB API with a static single-page frontend for the ClickWorker prototype.

## Prerequisites

- Node.js 18+
- A MongoDB database

## Setup

```bash
cp .env.example .env
# Set MONGODB_URI, JWT_SECRET, ADMIN_API_KEY, and ADMIN_PASSWORD in .env
pnpm install
pnpm start
```

The app is available at `http://localhost:3000`.

> Do not commit `.env`; it contains local credentials.