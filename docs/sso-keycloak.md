# Dashboard sign-in with Keycloak

Interactive users of the dashboard can sign in with MartinsTech SSO (Keycloak, OIDC Authorization Code + PKCE). Programmatic clients keep sending `X-API-Key`. Nothing in this flow replaces or weakens that check.

SSO is **off** unless all three of `OPENWA_SSO_ISSUER`, `OPENWA_SSO_CLIENT_ID`, and `OPENWA_SSO_REDIRECT_URL` are set. With them unset, the dashboard keeps the API-key form and every API route behaves as it does today.

This tree serves the dashboard and the API on one public origin (Traefik sends `/api` and `/socket.io` to the API, and everything else to the dashboard). The session cookie is host-scoped, `Path=/`, so the browser sends it to both. The login button is a normal link. No inline script and no new CDN were added, so the existing Helmet `script-src 'self'` policy still applies.

## What SRE creates in Keycloak

Realm: `MartinsTech` (Keycloak 26).

Create a client:

| Setting | Value |
| --- | --- |
| Client type | OpenID Connect |
| Client ID | `openwa` (or whatever `OPENWA_SSO_CLIENT_ID` will be) |
| Name | OpenWA |
| Always display in UI | Off |
| Client authentication | **Off** if no client secret will be set (public client, PKCE only). **On** only if `OPENWA_SSO_CLIENT_SECRET` will be set. |
| Authorization | Off |
| Authentication flow | Standard flow **on**. Direct access grants, implicit, and service account **off**. |
| Root URL | `https://<public-openwa-origin>/` |
| Home URL | `https://<public-openwa-origin>/` |
| Valid redirect URIs | `https://<public-openwa-origin>/api/auth/sso/callback` exactly. Add `http://localhost:2886/api/auth/sso/callback` only for a dev workstation. |
| Valid post logout redirect URIs | `https://<public-openwa-origin>/` |
| Web origins | `https://<public-openwa-origin>` (same origin; do not use `*`) |
| PKCE | S256. Required if the client is public. Leave it required for a confidential client too. |
| Proof Key for Code Exchange method | S256 |

Default client scopes should include `openid`, `profile`, and `roles`. The `roles` scope is what puts realm roles on the tokens. The access token's `aud` may be `account`; OpenWA accepts that when `azp` is this client id, which Keycloak sets by default.

### Role

1. Realm roles → Create role → name `openwa-user` (or the value you will put in `OPENWA_SSO_ROLE`).
2. Assign that role only to people who may use the dashboard (Role mapping on the user, or a group).
3. A client role with the same name on this client also works. Roles of other clients do not.

Users without the role get **HTTP 403** and no session cookie.

A successful login is authorized as an **admin** API principal for the life of the cookie. That matches what the dashboard already does with the admin key: sessions, webhooks, API-key management, and plugins. The Keycloak role is the allow-list; it is not a second, narrower permission model.

## Environment

Set these on the API process (`openwa-api`). All are optional. Example values below are fake.

```bash
# Required together, or SSO stays off
OPENWA_SSO_ISSUER=https://auth.example.com/realms/MartinsTech
OPENWA_SSO_CLIENT_ID=openwa
OPENWA_SSO_REDIRECT_URL=https://openwa.example/api/auth/sso/callback

# Omit for a public client. Never put this value in the dashboard bundle.
# OPENWA_SSO_CLIENT_SECRET=

# Realm or client role required to receive a session. Default: openwa-user
OPENWA_SSO_ROLE=openwa-user

# Session cookie lifetime in seconds. Default: 3600. Values below 60 are ignored.
OPENWA_SSO_SESSION_TTL=3600

# Default: true when NODE_ENV=production, otherwise false.
# Keep true behind HTTPS. Set false only for plain HTTP development.
OPENWA_SSO_COOKIE_SECURE=true

# Where Keycloak sends the browser after logout. Default: the origin of the redirect URL, plus `/`.
OPENWA_SSO_POST_LOGOUT_URL=https://openwa.example/

# Reverse proxies allowed to set X-Forwarded-For / X-Forwarded-Proto.
# Comma-separated IPs, IPv4 CIDRs, or the keyword loopback.
# Empty means those headers are ignored. There is no "trust everyone" setting.
OPENWA_TRUST_PROXY=127.0.0.1
```

`OPENWA_SSO_REDIRECT_URL` must be the **public** origin that serves both the dashboard and `/api`, not the container-internal `http://openwa-api:2785/...`. After login the browser is sent to `/` on that same origin.

`docker-compose.yml` passes these variables through. An empty issuer leaves SSO disabled.

Machine clients keep using `X-API-Key`:

- a key stored in the database, or
- `API_MASTER_KEY`, when that variable is non-empty. It is compared by SHA-256 and authorizes as admin. It is never written to the log. An empty value does not match.

## Reverse proxy

The API trusts `X-Forwarded-*` only when the TCP peer is listed in `OPENWA_TRUST_PROXY`. A client that connects directly cannot spoof its address by sending the header.

Configure the proxy to **overwrite** `X-Forwarded-For` with the address it observed (`$remote_addr` / the equivalent), and to set `X-Forwarded-Proto` to `https` when it terminates TLS. If the proxy appends instead of overwriting, a caller can prepend a fake address and OpenWA will read that left-most value.

For this stack the peer is whatever connects to `openwa-api:2785`: Traefik on the Docker bridge, or `tailscale serve` on loopback. Use that address, not the public client address. `loopback` covers `127.0.0.1` and `::1`.

The session cookie is `openwa_session`: `HttpOnly`, `SameSite=Lax`, `Secure` when configured, `Path=/`. `SameSite=Lax` is required so the browser still sends the login-transaction cookie on the top-level redirect back from Keycloak. The cookie value is a random id. The ID token stays in process memory for logout and is not logged. Logout redirects to Keycloak's `end_session_endpoint` with `id_token_hint` when discovery advertises one; that hint is the standard RP-initiated logout parameter and is not written to the log.

Sessions live in memory. Restarting the API drops them; users sign in again. There is no extra database.

## Rollback

Unset `OPENWA_SSO_ISSUER` (or the client id, or the redirect URL) and restart `openwa-api`. SSO routes return 404, the dashboard hides the SSO button, and API-key login is the only browser path. Existing API keys keep working. No migration to undo.

## Handoff for SRE

1. In Keycloak realm `MartinsTech`, create the OIDC client described above. Redirect URI: `https://<public-origin>/api/auth/sso/callback`. Post-logout URI: `https://<public-origin>/`. Web origin: `https://<public-origin>`. Standard flow only. PKCE S256. Public client unless you intentionally set a secret.
2. Create realm role `openwa-user` and assign it to the people who may open the dashboard.
3. On the API container set:
   - `OPENWA_SSO_ISSUER` = the realm issuer, for example `https://<keycloak-host>/realms/MartinsTech` (no trailing slash required)
   - `OPENWA_SSO_CLIENT_ID=openwa`
   - `OPENWA_SSO_REDIRECT_URL=https://<public-origin>/api/auth/sso/callback`
   - `OPENWA_SSO_POST_LOGOUT_URL=https://<public-origin>/`
   - `OPENWA_SSO_COOKIE_SECURE=true`
   - `OPENWA_TRUST_PROXY=<ip of the proxy that dials the API>`
   - leave `OPENWA_SSO_CLIENT_SECRET` unset for a public client
   - do not change `API_MASTER_KEY`
4. Restart only `openwa-api`. Do not rotate API keys.
5. Smoke test:
   - `GET /api/auth/sso/session` returns `{"ssoEnabled":true,"authenticated":false}` before login.
   - Open the dashboard, click **Entrar com MartinsTech SSO**, sign in as a user who has `openwa-user`, and land on the dashboard.
   - Sign in as a user without that role and confirm a 403 page and that the dashboard is still logged out.
   - Call any API route with `X-API-Key: <API_MASTER_KEY or a database key>` and confirm it still succeeds with no cookie.
   - Log out and confirm the browser returns from Keycloak to the dashboard login.
   - Unset the three required SSO variables, restart, and confirm the API-key form is back and `/api/auth/sso/login` is 404.
