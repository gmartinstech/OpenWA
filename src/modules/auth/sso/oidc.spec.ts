import { createHash, generateKeyPairSync, sign, type KeyObject } from 'crypto';
import { collectRoles, createPkce, JwtError, verifyJwt, type JsonWebKeyWithKid } from './oidc';

function expectJwtFailure(run: () => void, reason: string): void {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(JwtError);
    expect((error as JwtError).reason).toBe(reason);
    return;
  }
  throw new Error(`expected JwtError ${reason}`);
}

function b64url(value: Buffer | string): string {
  const buffer = typeof value === 'string' ? Buffer.from(value) : value;
  return buffer.toString('base64url');
}

function signJwt(payload: Record<string, unknown>, key: KeyObject, alg: 'RS256' | 'ES256', kid: string): string {
  const header = b64url(JSON.stringify({ alg, typ: 'JWT', kid }));
  const body = b64url(JSON.stringify(payload));
  const data = `${header}.${body}`;
  const signature =
    alg === 'RS256'
      ? sign('RSA-SHA256', Buffer.from(data), key)
      : sign('sha256', Buffer.from(data), { key, dsaEncoding: 'ieee-p1363' });
  return `${data}.${b64url(signature)}`;
}

function publicJwk(publicKey: KeyObject, kid: string, alg: 'RS256' | 'ES256'): JsonWebKeyWithKid {
  const jwk = publicKey.export({ format: 'jwk' }) as JsonWebKeyWithKid;
  jwk.kid = kid;
  jwk.alg = alg;
  jwk.use = 'sig';
  return jwk;
}

describe('OIDC token checks', () => {
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const rsaJwk = publicJwk(rsa.publicKey, 'rsa-1', 'RS256');
  const ecJwk = publicJwk(ec.publicKey, 'ec-1', 'ES256');

  const baseClaims = () => ({
    iss: 'https://idp.example/realms/MartinsTech',
    sub: 'user-1',
    aud: 'openwa',
    exp: Math.floor(Date.now() / 1000) + 300,
    iat: Math.floor(Date.now() / 1000),
    nonce: 'nonce-1',
    preferred_username: 'gabriel',
  });

  it('builds an S256 PKCE challenge from the verifier', () => {
    const pkce = createPkce();
    expect(pkce.verifier.length).toBeGreaterThan(40);
    expect(createHash('sha256').update(pkce.verifier).digest('base64url')).toBe(pkce.challenge);
  });

  it('accepts an RS256 ID token with the expected issuer, audience, and nonce', () => {
    const token = signJwt(baseClaims(), rsa.privateKey, 'RS256', 'rsa-1');
    const claims = verifyJwt(token, [rsaJwk], {
      issuer: 'https://idp.example/realms/MartinsTech',
      audience: 'openwa',
      nonce: 'nonce-1',
    });
    expect(claims.sub).toBe('user-1');
    expect(claims.preferred_username).toBe('gabriel');
  });

  it('accepts an ES256 token', () => {
    const token = signJwt(baseClaims(), ec.privateKey, 'ES256', 'ec-1');
    const claims = verifyJwt(token, [ecJwk], {
      issuer: 'https://idp.example/realms/MartinsTech',
      audience: 'openwa',
      nonce: 'nonce-1',
    });
    expect(claims.sub).toBe('user-1');
  });

  it('rejects a bad signature, alg none, the wrong nonce, and an unknown kid', () => {
    const token = signJwt(baseClaims(), rsa.privateKey, 'RS256', 'rsa-1');
    const [header, payload] = token.split('.');
    expect(() =>
      verifyJwt(`${header}.${payload}.${b64url(Buffer.from('nope'))}`, [rsaJwk], {
        issuer: 'https://idp.example/realms/MartinsTech',
        audience: 'openwa',
        nonce: 'nonce-1',
      }),
    ).toThrow(JwtError);

    const noneHeader = b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }));
    expectJwtFailure(
      () =>
        verifyJwt(`${noneHeader}.${b64url(JSON.stringify(baseClaims()))}.x`, [rsaJwk], {
          issuer: 'https://idp.example/realms/MartinsTech',
          audience: 'openwa',
        }),
      'unsupported_alg',
    );

    expectJwtFailure(
      () =>
        verifyJwt(token, [rsaJwk], {
          issuer: 'https://idp.example/realms/MartinsTech',
          audience: 'openwa',
          nonce: 'other-nonce',
        }),
      'nonce',
    );

    expectJwtFailure(
      () =>
        verifyJwt(signJwt(baseClaims(), rsa.privateKey, 'RS256', 'missing'), [rsaJwk], {
          issuer: 'https://idp.example/realms/MartinsTech',
          audience: 'openwa',
          nonce: 'nonce-1',
        }),
      'unknown_kid',
    );
  });

  it('accepts a Keycloak access token whose aud is account when azp is the client', () => {
    const token = signJwt(
      { ...baseClaims(), aud: 'account', azp: 'openwa', nonce: undefined },
      rsa.privateKey,
      'RS256',
      'rsa-1',
    );
    const claims = verifyJwt(token, [rsaJwk], {
      issuer: 'https://idp.example/realms/MartinsTech',
      audience: 'openwa',
      accessToken: true,
    });
    expect(claims.azp).toBe('openwa');
  });

  it('collects realm roles and roles for this client only', () => {
    const roles = collectRoles(
      {
        realm_access: { roles: ['openwa-user', 'offline_access'] },
        resource_access: {
          openwa: { roles: ['dashboard'] },
          other: { roles: ['secret-admin'] },
        },
      },
      'openwa',
    );
    expect(roles).toEqual(['openwa-user', 'offline_access', 'dashboard']);
  });
});
