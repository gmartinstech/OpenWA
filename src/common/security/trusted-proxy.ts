import type { Request } from 'express';

const IPV4_MAPPED = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i;

export function normalizeIp(ip: string): string {
  const trimmed = ip.trim();
  const mapped = IPV4_MAPPED.exec(trimmed);
  if (mapped) return mapped[1];
  return trimmed;
}

/** Comma-separated proxy IPs, CIDRs, or the keyword `loopback`. Empty means trust nobody. */
export function parseTrustedProxies(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(',')
    .map(entry => entry.trim())
    .filter(entry => entry.length > 0 && !['false', 'off', '0'].includes(entry.toLowerCase()));
}

export function isTrustedProxy(peerIp: string, trusted: string[]): boolean {
  if (trusted.length === 0) return false;
  const peer = normalizeIp(peerIp);
  for (const entry of trusted) {
    if (entry.toLowerCase() === 'loopback') {
      if (peer === '127.0.0.1' || peer === '::1') return true;
      continue;
    }
    if (entry.includes('/')) {
      if (ipv4InCidr(peer, entry)) return true;
      continue;
    }
    if (normalizeIp(entry) === peer) return true;
  }
  return false;
}

export function resolveClientIp(request: Pick<Request, 'ip' | 'headers' | 'socket'>, trusted: string[]): string {
  const peer = normalizeIp(request.socket?.remoteAddress || request.ip || '');
  if (peer && isTrustedProxy(peer, trusted)) {
    const forwarded = request.headers['x-forwarded-for'];
    const raw = Array.isArray(forwarded) ? forwarded.join(',') : forwarded;
    const first = raw?.split(',')[0]?.trim();
    if (first) return normalizeIp(first);
  }
  return peer;
}

/**
 * Express `trust proxy` callback. Only the configured proxy peers may supply X-Forwarded-*.
 * A boolean `true` (trust everyone) is intentionally not supported.
 */
export function applyTrustProxy(
  app: { set(setting: string, value: unknown): void },
  env: NodeJS.ProcessEnv = process.env,
): string[] {
  const trusted = parseTrustedProxies(env.OPENWA_TRUST_PROXY);
  if (trusted.length === 0) {
    app.set('trust proxy', false);
    return trusted;
  }
  app.set('trust proxy', (ip: string) => isTrustedProxy(ip, trusted));
  return trusted;
}

function ipv4ToNumber(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let acc = 0;
  for (const octet of parts) {
    if (!/^\d{1,3}$/.test(octet)) return null;
    const value = Number(octet);
    if (value > 255) return null;
    acc = ((acc << 8) + value) >>> 0;
  }
  return acc;
}

function ipv4InCidr(ip: string, cidr: string): boolean {
  const [range, bitsRaw] = cidr.split('/');
  if (!range || bitsRaw === undefined || cidr.split('/').length !== 2) return false;
  const bits = Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const ipNum = ipv4ToNumber(ip);
  const rangeNum = ipv4ToNumber(range);
  if (ipNum === null || rangeNum === null) return false;
  if (bits === 0) return true;
  const mask = bits === 32 ? 0xffffffff : ~(2 ** (32 - bits) - 1) >>> 0;
  return (ipNum & mask) === (rangeNum & mask);
}
