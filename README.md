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

Sensitive endpoints use the MongoDB `rate_limits` collection for shared rate limiting. Limits are therefore enforced across all Node.js workers and application instances connected to the same database; expired buckets are removed automatically by a TTL index.

Registration requires SMS OTP verification through Twilio Verify. Configure `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, and `TWILIO_VERIFY_SERVICE_SID` in the server environment. These values are server-side secrets and must never be placed in frontend JavaScript. Twilio's free trial is suitable only for limited testing; production SMS delivery is usage-priced.

> Do not commit `.env`; it contains local credentials.
