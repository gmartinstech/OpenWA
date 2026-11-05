import { applyTrustProxy, isTrustedProxy, resolveClientIp } from './trusted-proxy';

function request(peer: string, forwarded?: string) {
  return {
    ip: peer,
    headers: forwarded ? { 'x-forwarded-for': forwarded } : {},
    socket: { remoteAddress: peer },
  } as Pick<import('express').Request, 'ip' | 'headers' | 'socket'>;
}

describe('trusted proxy client IP', () => {
  it('ignores X-Forwarded-For when no proxy is trusted', () => {
    const ip = resolveClientIp(request('10.0.0.8', '203.0.113.50, 10.0.0.8'), []);
    expect(ip).toBe('10.0.0.8');
  });

  it('uses the left-most X-Forwarded-For address when the peer is trusted', () => {
    const ip = resolveClientIp(request('10.0.0.8', '203.0.113.50, 10.0.0.8'), ['10.0.0.8']);
    expect(ip).toBe('203.0.113.50');
  });

  it('does not trust a peer outside the configured list', () => {
    const ip = resolveClientIp(request('192.0.2.10', '203.0.113.50'), ['10.0.0.8']);
    expect(ip).toBe('192.0.2.10');
  });

  it('treats loopback and IPv4-mapped loopback as trusted when asked', () => {
    expect(isTrustedProxy('::ffff:127.0.0.1', ['loopback'])).toBe(true);
    expect(isTrustedProxy('::1', ['loopback'])).toBe(true);
    expect(isTrustedProxy('10.1.1.1', ['loopback'])).toBe(false);
  });

  it('matches an IPv4 CIDR entry', () => {
    expect(isTrustedProxy('10.89.0.14', ['10.89.0.0/24'])).toBe(true);
    expect(isTrustedProxy('10.89.1.14', ['10.89.0.0/24'])).toBe(false);
  });

  it('installs a trust-proxy predicate that rejects unlisted peers', () => {
    let setting: unknown;
    applyTrustProxy(
      {
        set(_name: string, value: unknown) {
          setting = value;
        },
      },
      { OPENWA_TRUST_PROXY: '127.0.0.1' },
    );
    expect(typeof setting).toBe('function');
    const predicate = setting as (ip: string) => boolean;
    expect(predicate('127.0.0.1')).toBe(true);
    expect(predicate('8.8.8.8')).toBe(false);
  });

  it('disables trust proxy when the setting is empty', () => {
    let setting: unknown = 'unset';
    applyTrustProxy(
      {
        set(_name: string, value: unknown) {
          setting = value;
        },
      },
      {},
    );
    expect(setting).toBe(false);
  });
});
