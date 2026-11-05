# Dashboard sign-in with Keycloak

This document matches OpenWA **0.15.0** (`6444bacedf4bd0d0126bd5ee85f39b1af0c74b6c`, tag `v0.15.0`). The API serves the built dashboard from `dashboard/dist` on the same origin and injects a per-response CSP nonce into `index.html` (`__OPENWA_CSP_NONCE__`). The SSO login control is a normal link inside the bundled script. It does not add an inline script or a new CDN, so that nonce injection stays as it is.

Interactive users can sign in with MartinsTech SSO (Keycloak, OIDC Authorization Code + PKCE). Programmatic clients keep sending `X-API-Key`. `API_MASTER_KEY` is still only the bootstrap value for the first stored API key. It is not a second request-time credential.

SSO is **off** unless `OPENWA_SSO_ISSUER`, `OPENWA_SSO_CLIENT_ID`, and `OPENWA_SSO_REDIRECT_URL` are all set, the issuer is `https` (or loopback `http`), and the redirect URL is an `http` or `https` URL. With SSO off, the dashboard keeps the API-key form.

## Keycloak client

Realm `MartinsTech`, Keycloak 26.

| Setting | Value |
| --- | --- |
| Client type | OpenID Connect |
| Client ID | `openwa` |
| Client authentication | Off for a public client (PKCE only). On only if `OPENWA_SSO_CLIENT_SECRET` is set. The secret is never sent to the browser. |
| Standard flow | On. Implicit, direct access grants, and service account off. |
| PKCE | S256, required |
| Valid redirect URIs | `https://<public-origin>/api/auth/sso/callback` exactly |
| Valid post logout redirect URIs | `https://<public-origin>/` |
| Web origins | `https://<public-origin>` |
| Default scopes | `openid`, `profile`, `roles` |

Create realm role `openwa-user` (or the value of `OPENWA_SSO_ROLE`) and assign it to the people who may use the dashboard. A client role of the same name on **this** client also counts. Roles of other clients do not. The ID token `aud` must be this client. An access token is accepted only when `aud` or `azp` is this client, which is how Keycloak 26 emits `aud=account` plus `azp=<client id>`.

Users without the role get **403** and no session. A user who has the role receives an httpOnly session and the same API authorization as an admin key (`allowedSessions` empty), because that is what the dashboard uses today.

## Environment

```bash
OPENWA_SSO_ISSUER=https://auth.example.com/realms/MartinsTech
OPENWA_SSO_CLIENT_ID=openwa
# OPENWA_SSO_CLIENT_SECRET=          # omit for a public client
OPENWA_SSO_REDIRECT_URL=https://openwa.example/api/auth/sso/callback
OPENWA_SSO_ROLE=openwa-user
OPENWA_SSO_SESSION_TTL=3600          # seconds; values under 60 are ignored
OPENWA_SSO_COOKIE_SECURE=true        # default true when NODE_ENV=production
OPENWA_SSO_POST_LOGOUT_URL=https://openwa.example/
```

`OPENWA_SSO_REDIRECT_URL` is the public origin that serves the dashboard and `/api`. It is not taken from the `Host` header. Post-logout URLs on any other origin are ignored and replaced with that origin's `/`. `javascript:` and other non-HTTP values are ignored.

`OPENWA_SSO_POST_LOGOUT_URL` must be the same origin as the redirect URL. Keycloak's `end_session_endpoint` is taken from discovery and must be `https` when the issuer is `https`.

## Cookie, CSRF, WebSocket

`openwa_session` is `HttpOnly`, `SameSite=Lax`, `Path=/`, `Secure` when configured. The value is a random id created at login. It is not the OIDC `state`, not a caller-supplied cookie, and not the ID token. The ID token stays in process memory for logout and is not logged.

`SameSite=Lax` blocks a cross-site POST from sending the cookie. Cookie-authenticated `POST`, `PUT`, `PATCH`, and `DELETE` also require header `X-CSRF-Token` equal to the secret returned by `GET /api/auth/sso/session`. An API key does not need that header. Logout is `POST /api/auth/sso/logout` with the header; the JSON body contains `logoutUrl` for the browser to follow.

The `/events` WebSocket accepts the session cookie only when the handshake `Origin` is exactly the redirect URL's origin. A missing or foreign `Origin` is rejected. The session id is not put in the query string. There is no SSE dashboard stream; MCP keeps its own authentication.

Sessions and in-flight login transactions are in-memory, each capped at 10,000, with TTL. Restarting the API drops them. No new database.

## Reverse proxy

`X-Forwarded-For` is trusted only when the TCP peer matches `TRUSTED_PROXIES` (IP or IPv4 CIDR). That setting already exists in this version. Leave it empty to ignore the header. Do not set it to a value that means "trust everyone". Configure the proxy to append or replace the chain so the nearest untrusted hop is the client address; OpenWA walks the chain from the right and skips trusted hops.

Example for a proxy on the Docker bridge: `TRUSTED_PROXIES=172.18.0.0/16`. For tailscale serve on loopback, use the address that actually connects to the API.

## Rollback

Unset `OPENWA_SSO_ISSUER` (or the client id, or the redirect URL) and restart the API container. `/api/auth/sso/login` returns 404, the SSO button disappears, and API-key login is unchanged. Nothing to migrate.

## SRE handoff

1. In realm `MartinsTech`, create the public OIDC client above. Redirect `https://<public-origin>/api/auth/sso/callback`. Post-logout and web origin `https://<public-origin>/`. PKCE S256. Standard flow only.
2. Create realm role `openwa-user` and assign it.
3. On the API process set `OPENWA_SSO_ISSUER`, `OPENWA_SSO_CLIENT_ID`, `OPENWA_SSO_REDIRECT_URL`, `OPENWA_SSO_COOKIE_SECURE=true`, and `TRUSTED_PROXIES` to the proxy that dials the API. Leave the client secret unset. Do not change `API_MASTER_KEY`.
4. Restart the API process only. It must be this 0.15.0 build (or a later build that contains this change), serving `dashboard/dist` itself.
5. Smoke test: `GET /api/auth/sso/session` is `ssoEnabled: true` before login; the button **Entrar com MartinsTech SSO** lands a role-holder on the dashboard; a user without the role gets 403 and no cookie; `X-API-Key` still works with no CSRF header; a cookie `POST` without `X-CSRF-Token` is 403; logout returns through Keycloak. Rollback is unsetting the three SSO variables and restarting.
