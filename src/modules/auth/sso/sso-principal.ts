import { ApiKey, ApiKeyRole } from '../entities/api-key.entity';
import { loadSsoConfig } from './sso.config';
import { SessionStore, type StoredSession } from './session-store';

export type SessionAuth =
  | { status: 'disabled' }
  | { status: 'absent' }
  | { status: 'expired' }
  | { status: 'ok'; apiKey: ApiKey };

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
  return {
    id: 'sso',
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
  return { status: 'ok', apiKey: sessionToApiKey(session) };
}
