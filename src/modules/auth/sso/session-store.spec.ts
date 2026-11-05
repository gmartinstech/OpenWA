import { SessionStore } from './session-store';

describe('SessionStore', () => {
  it('returns a pending login once and then forgets it', () => {
    const store = new SessionStore();
    const now = 1_000_000;
    expect(
      store.putPending({ state: 'state-1', nonce: 'nonce-1', codeVerifier: 'verifier', expiresAt: now + 1000 }, now),
    ).toBe(true);

    expect(store.takePending('state-1', now + 10)?.nonce).toBe('nonce-1');
    expect(store.takePending('state-1', now + 10)).toBeUndefined();
  });

  it('rejects an expired pending login and an expired session', () => {
    const store = new SessionStore();
    const now = 1_000_000;
    store.putPending({ state: 'state-1', nonce: 'nonce-1', codeVerifier: 'verifier', expiresAt: now + 1000 }, now);
    expect(store.takePending('state-1', now + 1000)).toBeUndefined();

    const session = store.createSession({
      subject: 'sub',
      username: 'gabriel',
      idToken: 'id-token',
      ttlSeconds: 60,
      now,
    });
    expect(session).toBeDefined();
    expect(store.getSession(session!.id, now + 60_000)).toBeUndefined();
  });

  it('deletes a live session', () => {
    const store = new SessionStore();
    const session = store.createSession({
      subject: 'sub',
      username: 'gabriel',
      idToken: 'id-token',
      ttlSeconds: 60,
    });
    expect(store.deleteSession(session!.id)?.subject).toBe('sub');
    expect(store.getSession(session!.id)).toBeUndefined();
  });
});
