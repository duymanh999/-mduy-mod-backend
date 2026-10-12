# MDUY MOD FF backend

Render settings:
- Build: `npm install`
- Start: `npm start`
- Node 20+

Environment variables:
- `LINK4M_API_TOKEN` — Link4m API token (keep secret)
- `FRONTEND_URL` — exact GitHub Pages origin, e.g. `https://duymanh999.github.io`
- `PUBLIC_BASE_URL` — Render service URL, e.g. `https://mduy-mod-backend.onrender.com`

Important:
- This starter limits each IP to 3 creations per UTC day in memory.
- Render restarts can reset the in-memory counters/jobs.
- The current Link4m integration assumes the API returns `shortenedUrl`.
- A provider callback/postback is needed for strong proof that a shortlink was completed. This starter does NOT claim that a redirect alone is secure verification.
