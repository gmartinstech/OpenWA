import { createHash, createPublicKey, createVerify, randomBytes, timingSafeEqual, type webcrypto } from 'crypto';

type JsonWebKey = webcrypto.JsonWebKey;

export type JwtFailure = 'malformed' | 'unsupported_alg' | 'unknown_kid' | 'bad_signature' | 'claims' | 'nonce';

export class JwtError extends Error {
  constructor(readonly reason: JwtFailure) {
    super(reason);
  }
}

export class DiscoveryError extends Error {
  constructor() {
    super('discovery');
  }
}

export interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  end_session_endpoint?: string;
}

export interface JsonWebKeyWithKid extends JsonWebKey {
  kid?: string;
  use?: string;
  alg?: string;
}

export interface VerifiedClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  nonce?: string;
  azp?: string;
  preferred_username?: string;
  realm_access?: { roles?: string[] };
  resource_access?: Record<string, { roles?: string[] }>;
  roles?: string[];
  raw: Record<string, unknown>;
}

export function createPkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

export function randomToken(): string {
  return randomBytes(32).toString('base64url');
}

export function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export function collectRoles(claims: Record<string, unknown>, clientId: string): string[] {
  const roles: string[] = [];
  const realm = claims.realm_access;
  if (isRecord(realm) && Array.isArray(realm.roles)) {
    for (const role of realm.roles) {
      if (typeof role === 'string') roles.push(role);
    }
  }
  const resource = claims.resource_access;
  if (isRecord(resource)) {
    const client = resource[clientId];
    if (isRecord(client) && Array.isArray(client.roles)) {
      for (const role of client.roles) {
        if (typeof role === 'string') roles.push(role);
      }
    }
  }
  return roles;
}

export async function fetchDiscovery(issuer: string, fetchImpl: typeof fetch): Promise<OidcDiscovery> {
  const url = `${issuer}/.well-known/openid-configuration`;
  const body = await fetchJson(url, { method: 'GET' }, fetchImpl);
  if (!isRecord(body)) throw new DiscoveryError();
  const discovery = parseDiscovery(body);
  assertDiscovery(discovery, issuer);
  return discovery;
}

export async function fetchJwks(jwksUri: string, fetchImpl: typeof fetch): Promise<JsonWebKeyWithKid[]> {
  const body = await fetchJson(jwksUri, { method: 'GET' }, fetchImpl);
  if (!isRecord(body) || !Array.isArray(body.keys)) throw new DiscoveryError();
  return body.keys.filter(isJwk);
}

export async function exchangeAuthorizationCode(
  input: {
    tokenEndpoint: string;
    code: string;
    redirectUri: string;
    clientId: string;
    codeVerifier: string;
    clientSecret?: string;
  },
  fetchImpl: typeof fetch,
): Promise<{ idToken: string; accessToken?: string }> {
  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    code: input.code,
    redirect_uri: input.redirectUri,
    client_id: input.clientId,
    code_verifier: input.codeVerifier,
  });
  if (input.clientSecret) form.set('client_secret', input.clientSecret);

  const body = await fetchJson(
    input.tokenEndpoint,
    {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: form.toString(),
    },
    fetchImpl,
  );
  if (!isRecord(body) || typeof body.id_token !== 'string' || body.id_token.length === 0) {
    throw new JwtError('malformed');
  }
  const accessToken = typeof body.access_token === 'string' ? body.access_token : undefined;
  return { idToken: body.id_token, accessToken };
}

export function verifyJwt(
  token: string,
  keys: JsonWebKeyWithKid[],
  options: { issuer: string; audience: string; nonce?: string; accessToken?: boolean },
): VerifiedClaims {
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some(part => part.length === 0)) throw new JwtError('malformed');
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  let header: Record<string, unknown>;
  try {
    header = parseJsonObject(Buffer.from(encodedHeader, 'base64url').toString('utf8'));
  } catch {
    throw new JwtError('malformed');
  }
  const alg = header.alg;
  if (alg !== 'RS256' && alg !== 'ES256') throw new JwtError('unsupported_alg');

  const kid = typeof header.kid === 'string' ? header.kid : undefined;
  const candidates = selectKeys(keys, alg, kid);
  if (candidates.length === 0) throw new JwtError('unknown_kid');

  const signed = `${encodedHeader}.${encodedPayload}`;
  const signature = Buffer.from(encodedSignature, 'base64url');
  const verified = candidates.some(key => verifySignature(alg, signed, signature, key));
  if (!verified) throw new JwtError('bad_signature');

  let payload: Record<string, unknown>;
  try {
    payload = parseJsonObject(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
  } catch {
    throw new JwtError('malformed');
  }
  return validateClaims(payload, options);
}

function selectKeys(keys: JsonWebKeyWithKid[], alg: 'RS256' | 'ES256', kid: string | undefined): JsonWebKeyWithKid[] {
  const expectedKty = alg === 'RS256' ? 'RSA' : 'EC';
  return keys.filter(key => {
    if (key.kty !== expectedKty) return false;
    if (key.use && key.use !== 'sig') return false;
    if (key.alg && key.alg !== alg) return false;
    if (kid) return key.kid === kid;
    return true;
  });
}

function verifySignature(alg: 'RS256' | 'ES256', signed: string, signature: Buffer, jwk: JsonWebKeyWithKid): boolean {
  try {
    const key = createPublicKey({ key: jwk, format: 'jwk' });
    if (alg === 'RS256') {
      return createVerify('RSA-SHA256').update(signed).verify(key, signature);
    }
    return createVerify('SHA256').update(signed).verify({ key, dsaEncoding: 'ieee-p1363' }, signature);
  } catch {
    return false;
  }
}

function validateClaims(
  claims: Record<string, unknown>,
  options: { issuer: string; audience: string; nonce?: string; accessToken?: boolean },
): VerifiedClaims {
  if (typeof claims.iss !== 'string' || claims.iss !== options.issuer) throw new JwtError('claims');
  if (typeof claims.sub !== 'string' || claims.sub.length === 0) throw new JwtError('claims');
  const aud = claims.aud;
  const audiences =
    typeof aud === 'string' ? [aud] : Array.isArray(aud) ? aud.filter(item => typeof item === 'string') : [];
  if (audiences.length === 0) throw new JwtError('claims');
  const azp = typeof claims.azp === 'string' ? claims.azp : undefined;
  if (options.accessToken) {
    const audienceOk = audiences.includes(options.audience) || azp === options.audience;
    if (!audienceOk) throw new JwtError('claims');
  } else if (!audiences.includes(options.audience)) {
    throw new JwtError('claims');
  }
  if (!options.accessToken && audiences.length > 1 && azp && azp !== options.audience) {
    throw new JwtError('claims');
  }

  const now = Math.floor(Date.now() / 1000);
  const skew = 60;
  if (typeof claims.exp !== 'number' || claims.exp + skew < now) throw new JwtError('claims');
  if (typeof claims.nbf === 'number' && claims.nbf - skew > now) throw new JwtError('claims');

  if (options.nonce !== undefined) {
    if (typeof claims.nonce !== 'string' || !safeEqual(claims.nonce, options.nonce)) throw new JwtError('nonce');
  }

  return {
    iss: claims.iss,
    sub: claims.sub,
    aud: audiences.length === 1 ? audiences[0] : audiences,
    exp: claims.exp,
    nonce: typeof claims.nonce === 'string' ? claims.nonce : undefined,
    azp,
    preferred_username: typeof claims.preferred_username === 'string' ? claims.preferred_username : undefined,
    raw: claims,
  };
}

function parseDiscovery(body: Record<string, unknown>): OidcDiscovery {
  if (
    typeof body.issuer !== 'string' ||
    typeof body.authorization_endpoint !== 'string' ||
    typeof body.token_endpoint !== 'string' ||
    typeof body.jwks_uri !== 'string'
  ) {
    throw new DiscoveryError();
  }
  return {
    issuer: body.issuer,
    authorization_endpoint: body.authorization_endpoint,
    token_endpoint: body.token_endpoint,
    jwks_uri: body.jwks_uri,
    end_session_endpoint: typeof body.end_session_endpoint === 'string' ? body.end_session_endpoint : undefined,
  };
}

function assertDiscovery(discovery: OidcDiscovery, issuer: string): void {
  if (discovery.issuer.replace(/\/+$/, '') !== issuer) throw new DiscoveryError();
  let issuerUrl: URL;
  try {
    issuerUrl = new URL(issuer);
  } catch {
    throw new DiscoveryError();
  }
  if (issuerUrl.protocol !== 'https:' && issuerUrl.protocol !== 'http:') throw new DiscoveryError();
  const endpoints = [
    discovery.authorization_endpoint,
    discovery.token_endpoint,
    discovery.jwks_uri,
    discovery.end_session_endpoint,
  ];
  for (const endpoint of endpoints) {
    if (!endpoint) continue;
    let url: URL;
    try {
      url = new URL(endpoint);
    } catch {
      throw new DiscoveryError();
    }
    if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new DiscoveryError();
    if (issuerUrl.protocol === 'https:' && url.protocol !== 'https:') throw new DiscoveryError();
  }
}

async function fetchJson(url: string, init: RequestInit, fetchImpl: typeof fetch): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const response = await fetchImpl(url, { ...init, redirect: 'error', signal: controller.signal });
    if (!response.ok) throw new DiscoveryError();
    const text = await response.text();
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new DiscoveryError();
    }
  } catch (error) {
    if (error instanceof DiscoveryError || error instanceof JwtError) throw error;
    throw new DiscoveryError();
  } finally {
    clearTimeout(timer);
  }
}

function parseJsonObject(text: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(text);
  if (!isRecord(parsed)) throw new JwtError('malformed');
  return parsed;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isJwk(value: unknown): value is JsonWebKeyWithKid {
  return isRecord(value) && typeof value.kty === 'string';
}
