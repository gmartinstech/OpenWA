import { createHash, timingSafeEqual } from 'crypto';
import { ApiKey, ApiKeyRole } from '../entities/api-key.entity';
import { loadSsoConfig } from './sso.config';
import { SessionStore, type StoredSession } from './session-store';

export type SessionAuth =
  | { status: 'disabled' }
  | { status: 'absent' }
  | { status: 'expired' }
  | { status: 'ok'; apiKey: ApiKey; csrfToken: string; sessionId: string };

export function readCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    if (key !== name) continue;
    try {
      return decodeURIComponent(part.slice(eq + 1).trim());
    } catch {
      return undefined;
    }
  }
  return undefined;
}

/** A signed-in dashboard user is authorized as an admin API key, which is what the dashboard uses today. */
export function sessionToApiKey(session: StoredSession): ApiKey {
  // Hash, don't embed, the cookie value: this id is written to logs and the socket map.
  const id = `sso:${createHash('sha256').update(session.id).digest('hex').slice(0, 16)}`;
  return {
    id,
    name: `sso:${session.username}`.slice(0, 100),
    keyHash: '',
    keyPrefix: 'sso',
    role: ApiKeyRole.ADMIN,
    allowedIps: null,
    allowedSessions: null,
    isActive: true,
    expiresAt: new Date(session.expiresAt),
    lastUsedAt: null,
    usageCount: 0,
    createdAt: session.createdAt,
    updatedAt: session.createdAt,
  };
}

export function resolveSessionAuth(
  store: SessionStore,
  cookieHeader: string | undefined,
  env: NodeJS.ProcessEnv = process.env,
): SessionAuth {
  const config = loadSsoConfig(env);
  if (!config.enabled) return { status: 'disabled' };
  const sessionId = readCookie(cookieHeader, config.sessionCookieName);
  if (!sessionId) return { status: 'absent' };
  const session = store.getSession(sessionId);
  if (!session) return { status: 'expired' };
  return { status: 'ok', apiKey: sessionToApiKey(session), csrfToken: session.csrfToken, sessionId: session.id };
}

export function isSafeHttpMethod(method: string | undefined): boolean {
  const normalized = (method ?? '').toUpperCase();
  return normalized === 'GET' || normalized === 'HEAD' || normalized === 'OPTIONS';
}

export function csrfHeaderMatches(header: string | string[] | undefined, expected: string): boolean {
  if (typeof header !== 'string' || header.length === 0 || expected.length === 0) return false;
  const presented = Buffer.from(header);
  const actual = Buffer.from(expected);
  if (presented.length !== actual.length) return false;
  return timingSafeEqual(presented, actual);
}

/** Browser Origin must be exactly the origin of the configured redirect URL. Missing Origin is rejected. */
export function isAllowedSsoOrigin(origin: string | undefined, allowedOrigin: string | undefined): boolean {
  if (!origin || !allowedOrigin) return false;
  try {
    return new URL(origin).origin === new URL(allowedOrigin).origin;
  } catch {
    return false;
  }
}

export function ssoAllowedOrigin(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const config = loadSsoConfig(env);
  if (!config.enabled) return undefined;
  try {
    return new URL(config.redirectUrl).origin;
  } catch {
    return undefined;
  }
}
