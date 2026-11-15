# StudyPoint backend

Node.js API for StudyPoint. It handles member accounts, credits, uploads, moderation, reader reports, and Paystack payments. The repository contains no seeded member accounts or sample documents.

## Deploy on Render

1. In Render, create a **Web Service** and connect `miclovesellie-alt/studypoint_backend`.
2. Leave Root Directory blank. Use Build Command `npm install` and Start Command `npm start`.
3. Set Health Check Path to `/api/health`.
4. Add a persistent disk mounted at `/opt/render/project/src/storage`, then set `STUDYPOINT_DATA_DIR` to that same path. Without persistent storage, Render's default filesystem is ephemeral and member data/uploads will be lost on deploy. The JSON store is single-instance, so do not scale this service to multiple instances.
5. Add the environment variables below and deploy. Render supplies `PORT`; this server binds to it on `0.0.0.0` automatically.

A Render persistent disk requires a paid web service. For a free or multi-instance deployment, use a managed database and object storage instead of this JSON file store.

## Environment variables

Set these in Render's Environment panel. Keep secret values out of Git.

- `STUDYPOINT_ADMIN_EMAIL` — administrator email; configured for the account provided for this project by default.
- `STUDYPOINT_ADMIN_PASSWORD` — choose and set this password privately in Render. The server does not generate or log it.
- `PAYSTACK_SECRET_KEY` — required to enable checkout.
- `PAYSTACK_WEBHOOK_SECRET` — webhook signing secret; recommended.
- `STUDYPOINT_PUBLIC_URL` — the Render HTTPS service URL, used for backend configuration.
- `STUDYPOINT_DATA_DIR` — `/opt/render/project/src/storage` when using the disk above.
- `STUDYPOINT_FRONTEND_URL` — the Vercel custom HTTPS domain, including `https://`.
- `STUDYPOINT_ALLOWED_ORIGIN` — the same exact Vercel origin, without a path or trailing slash.

For reliable browser sessions, use sibling subdomains under the same domain for the frontend and API (for example, an app subdomain on Vercel and an API subdomain on Render). Render can attach the API subdomain to the web service and show the exact DNS target. The configured document price is GH₵10 per credit, in GHS. Paystack checkout initializes on the server and credits are added only after transaction verification confirms the reference, status, currency, and exact amount. The webhook route is `/api/paystack/webhook`; subscribe it to `charge.success`.

## Local development

Use Node.js 18 or newer. Run `npm start` and open `http://127.0.0.1:4173`. The JSON database and files use `data/` by default; this directory is gitignored.

## API

- `GET /api/health`, `GET /api/bootstrap`
- `POST /api/auth/register`, `/api/auth/login`, `/api/auth/logout`
- `POST /api/documents/:id/save`, `/api/documents/:id/download`, `GET /api/documents/:id/preview`
- `POST /api/uploads`, `POST /api/reports`
- `POST /api/payments/initialize`, `/api/payments/verify`, `/api/paystack/webhook`
- `/api/admin/*`

