import { Injectable } from '@nestjs/common';
import { randomBytes } from 'crypto';

export interface PendingLogin {
  state: string;
  nonce: string;
  codeVerifier: string;
  expiresAt: number;
}

export interface StoredSession {
  id: string;
  /** Per-session CSRF secret. Never the session id, so a stolen page cannot replay the cookie alone. */
  csrfToken: string;
  subject: string;
  username: string;
  idToken: string;
  createdAt: Date;
  expiresAt: number;
}

export const DEFAULT_MAX_SSO_ENTRIES = 10_000;

@Injectable()
export class SessionStore {
  private readonly sessions = new Map<string, StoredSession>();
  private readonly pending = new Map<string, PendingLogin>();
  maxEntries = DEFAULT_MAX_SSO_ENTRIES;

  putPending(entry: PendingLogin, now = Date.now()): boolean {
    this.sweep(now);
    if (this.pending.size >= this.maxEntries) return false;
    this.pending.set(entry.state, entry);
    return true;
  }

  takePending(state: string, now = Date.now()): PendingLogin | undefined {
    const entry = this.pending.get(state);
    if (!entry) return undefined;
    this.pending.delete(state);
    if (entry.expiresAt <= now) return undefined;
    return entry;
  }

  createSession(input: {
    subject: string;
    username: string;
    idToken: string;
    ttlSeconds: number;
    now?: number;
  }): StoredSession | undefined {
    const now = input.now ?? Date.now();
    this.sweep(now);
    if (this.sessions.size >= this.maxEntries) return undefined;
    const session: StoredSession = {
      id: randomBytes(32).toString('base64url'),
      csrfToken: randomBytes(32).toString('base64url'),
      subject: input.subject,
      username: input.username,
      idToken: input.idToken,
      createdAt: new Date(now),
      expiresAt: now + input.ttlSeconds * 1000,
    };
    this.sessions.set(session.id, session);
    return session;
  }

  getSession(id: string, now = Date.now()): StoredSession | undefined {
    const session = this.sessions.get(id);
    if (!session) return undefined;
    if (session.expiresAt <= now) {
      this.sessions.delete(id);
      return undefined;
    }
    return session;
  }

  deleteSession(id: string): StoredSession | undefined {
    const session = this.sessions.get(id);
    this.sessions.delete(id);
    return session;
  }

  private sweep(now: number): void {
    for (const [key, value] of this.pending) {
      if (value.expiresAt <= now) this.pending.delete(key);
    }
    for (const [key, value] of this.sessions) {
      if (value.expiresAt <= now) this.sessions.delete(key);
    }
  }
}
