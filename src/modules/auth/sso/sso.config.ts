export const SSO_SESSION_COOKIE = 'openwa_session';
export const SSO_TX_COOKIE = 'openwa_sso_tx';
export const DEFAULT_SSO_ROLE = 'openwa-user';
export const DEFAULT_SESSION_TTL_SECONDS = 3600;
export const SSO_TX_TTL_SECONDS = 600;

export interface SsoConfig {
  enabled: boolean;
  issuer: string;
  clientId: string;
  clientSecret?: string;
  redirectUrl: string;
  role: string;
  sessionTtlSeconds: number;
  cookieSecure: boolean;
  sessionCookieName: string;
  txCookieName: string;
  postLogoutUrl: string;
}

export interface SessionCookieOptions {
  httpOnly: true;
  sameSite: 'lax';
  secure: boolean;
  path: string;
  maxAge?: number;
}

export function loadSsoConfig(env: NodeJS.ProcessEnv = process.env): SsoConfig {
  const issuer = stripTrailingSlash(env.OPENWA_SSO_ISSUER?.trim() ?? '');
  const clientId = env.OPENWA_SSO_CLIENT_ID?.trim() ?? '';
  const redirectUrl = env.OPENWA_SSO_REDIRECT_URL?.trim() ?? '';
  const secret = env.OPENWA_SSO_CLIENT_SECRET?.trim() ?? '';
  const enabled = assertIssuerIsTrusted(issuer) && clientId.length > 0 && isUsableHttpUrl(redirectUrl);

  return {
    enabled,
    issuer,
    clientId,
    clientSecret: secret || undefined,
    redirectUrl,
    role: env.OPENWA_SSO_ROLE?.trim() || DEFAULT_SSO_ROLE,
    sessionTtlSeconds: parseTtl(env.OPENWA_SSO_SESSION_TTL),
    cookieSecure: parseCookieSecure(env.OPENWA_SSO_COOKIE_SECURE, env.NODE_ENV),
    sessionCookieName: SSO_SESSION_COOKIE,
    txCookieName: SSO_TX_COOKIE,
    postLogoutUrl: sameOriginPostLogout(env.OPENWA_SSO_POST_LOGOUT_URL?.trim() ?? '', redirectUrl),
  };
}

export function sessionCookieOptions(config: SsoConfig): SessionCookieOptions {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.cookieSecure,
    path: '/',
    maxAge: config.sessionTtlSeconds * 1000,
  };
}

export function txCookieOptions(config: SsoConfig): SessionCookieOptions {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.cookieSecure,
    path: '/api/auth/sso',
    maxAge: SSO_TX_TTL_SECONDS * 1000,
  };
}

function stripTrailingSlash(value: string): string {
  return value.replace(/\/+$/, '');
}

function parseTtl(raw: string | undefined): number {
  if (!raw?.trim()) return DEFAULT_SESSION_TTL_SECONDS;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < 60) return DEFAULT_SESSION_TTL_SECONDS;
  return Math.floor(parsed);
}

function parseCookieSecure(raw: string | undefined, nodeEnv: string | undefined): boolean {
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  return nodeEnv === 'production';
}

/** Public issuers must be https. Loopback http is allowed so tests and local Keycloak work. */
export function assertIssuerIsTrusted(issuer: string): boolean {
  let url: URL;
  try {
    url = new URL(issuer);
  } catch {
    return false;
  }
  if (url.protocol === 'https:') return true;
  if (url.protocol !== 'http:') return false;
  return url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '::1';
}

function isUsableHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:';
  } catch {
    return false;
  }
}

function sameOriginPostLogout(candidate: string, redirectUrl: string): string {
  const fallback = defaultPostLogout(redirectUrl);
  if (!candidate) return fallback;
  const safe = safeHttpUrl(candidate, fallback);
  try {
    if (new URL(safe).origin === new URL(redirectUrl).origin) return safe;
  } catch {
    return fallback;
  }
  return fallback;
}

function safeHttpUrl(value: string, fallback: string): string {
  if (value.startsWith('/') && !value.startsWith('//')) return value;
  try {
    const parsed = new URL(value);
    if (parsed.protocol === 'https:' || parsed.protocol === 'http:') return value;
  } catch {
    return fallback;
  }
  return fallback;
}

function defaultPostLogout(redirectUrl: string): string {
  if (!redirectUrl) return '/';
  try {
    return `${new URL(redirectUrl).origin}/`;
  } catch {
    return '/';
  }
}
