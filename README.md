# Kittylol

Kittylol is a dark, responsive script-management dashboard for server-side protection of Roblox Lua/Luau scripts.

## What is included

- Cookie-based JWT authentication with bcrypt password hashing.
- Prisma schema for users, encrypted scripts, revisions, tokens, and request logs.
- AES-256-GCM encryption at rest for source code. Source is deliberately omitted from management API responses.
- Token loader endpoint: `/files/v4/loader/:token.lua`.
- Disabled-token checks, per-IP hashed request logs, basic browser hotlink protection, and a 30 requests/minute/IP limit.
- Dashboard for create, edit, delete, enable/disable, tokenized loader copying, revisions, and request totals.
- Helmet, CORS allow-list, request size limit, secure httpOnly cookie settings, and production environment configuration.

## Run locally

```bash
cp .env.example .env
# Set SOURCE_ENCRYPTION_KEY to a base64 encoding of exactly 32 random bytes
npm install
npm run db:push
npm run dev
```

The UI runs at `http://localhost:5173`; the API runs at `http://localhost:3000`.

The generated loader is:

```lua
loadstring(game:HttpGet("https://api.KITTYLOL_DOMAIN/files/v4/loader/<token>.lua"))()
```

Set `APP_URL` and `API_URL` to production origins and `COOKIE_SECURE=true` behind HTTPS. Use PostgreSQL instead of SQLite for production by changing the Prisma provider and `DATABASE_URL`. Put the API behind TLS and a reverse proxy/WAF. Do not log decrypted source, and rotate `JWT_SECRET`/encryption keys using a managed secret store.

The protection is intentionally server-side and does not claim to make Lua/Luau dump or decompile-proof. A client that receives executable source can potentially inspect it; Kittylol focuses on access control, token validation, rate limiting, versioning, audit logs, and keeping source out of the frontend and management API.
