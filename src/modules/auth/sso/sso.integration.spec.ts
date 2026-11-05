import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'http';
import { createHash, generateKeyPairSync, sign, type KeyObject } from 'crypto';
import { Controller, Get, INestApplication, UnauthorizedException } from '@nestjs/common';
import { APP_GUARD, Reflector } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import type { App } from 'supertest/types';
import { ApiKey, ApiKeyRole } from '../entities/api-key.entity';
import { CurrentApiKey, RequireRole } from '../decorators/auth.decorators';
import { ApiKeyGuard } from '../guards/api-key.guard';
import { AuthService } from '../auth.service';
import { SessionStore } from './session-store';
import { SsoController } from './sso.controller';
import { SsoService } from './sso.service';
import type { JsonWebKeyWithKid } from './oidc';

@Controller('probe')
class ProbeController {
  @Get()
  @RequireRole(ApiKeyRole.ADMIN)
  get(@CurrentApiKey() apiKey: ApiKey) {
    return { ok: true, role: apiKey.role, name: apiKey.name };
  }
}

function b64url(value: Buffer | string): string {
  const buffer = typeof value === 'string' ? Buffer.from(value) : value;
  return buffer.toString('base64url');
}

function cookieLines(value: string | string[] | undefined): string[] {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function cookieHeader(lines: string[]): string {
  return lines.map(line => line.split(';')[0]).join('; ');
}

class FakeKeycloak {
  tokenHits = 0;
  challenge = '';
  nonce = '';
  realmRoles = ['openwa-user'];
  accessRoles: string[] | null = null;
  readonly secret = 'test-client-secret';
  lastIdToken = '';
  issuer = '';
  private server: Server | null = null;
  private readonly privateKey: KeyObject;
  private readonly jwk: JsonWebKeyWithKid;

  constructor() {
    const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
    this.privateKey = pair.privateKey;
    this.jwk = pair.publicKey.export({ format: 'jwk' });
    this.jwk.kid = 'test';
    this.jwk.alg = 'RS256';
    this.jwk.use = 'sig';
  }

  async start(): Promise<void> {
    this.server = createServer((req, res) => {
      void this.handle(req, res);
    });
    await new Promise<void>(resolve => this.server!.listen(0, '127.0.0.1', resolve));
    const address = this.server.address();
    if (!address || typeof address === 'string') throw new Error('fake keycloak failed to bind');
    this.issuer = `http://127.0.0.1:${address.port}/realms/MartinsTech`;
  }

  async stop(): Promise<void> {
    if (!this.server) return;
    await new Promise<void>((resolve, reject) => this.server!.close(err => (err ? reject(err) : resolve())));
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url || '/', this.issuer);
    if (req.method === 'GET' && url.pathname.endsWith('/.well-known/openid-configuration')) {
      this.send(res, 200, {
        issuer: this.issuer,
        authorization_endpoint: `${this.issuer}/protocol/openid-connect/auth`,
        token_endpoint: `${this.issuer}/protocol/openid-connect/token`,
        jwks_uri: `${this.issuer}/protocol/openid-connect/certs`,
        end_session_endpoint: `${this.issuer}/protocol/openid-connect/logout`,
      });
      return;
    }
    if (req.method === 'GET' && url.pathname.endsWith('/protocol/openid-connect/certs')) {
      this.send(res, 200, { keys: [this.jwk] });
      return;
    }
    if (req.method === 'POST' && url.pathname.endsWith('/protocol/openid-connect/token')) {
      const body = await readBody(req);
      const form = new URLSearchParams(body);
      this.tokenHits += 1;
      const verifier = form.get('code_verifier') || '';
      const challenge = createHash('sha256').update(verifier).digest('base64url');
      if (form.get('client_secret') !== this.secret || challenge !== this.challenge || !form.get('code')) {
        this.send(res, 400, { error: 'invalid_grant' });
        return;
      }
      const now = Math.floor(Date.now() / 1000);
      const idToken = this.sign({
        iss: this.issuer,
        sub: 'user-1',
        aud: 'openwa',
        exp: now + 300,
        iat: now,
        nonce: this.nonce,
        preferred_username: 'gabriel',
        realm_access: { roles: this.realmRoles },
      });
      const accessToken = this.sign({
        iss: this.issuer,
        sub: 'user-1',
        aud: 'account',
        azp: 'openwa',
        exp: now + 300,
        iat: now,
        realm_access: { roles: this.accessRoles ?? this.realmRoles },
      });
      this.lastIdToken = idToken;
      this.send(res, 200, { id_token: idToken, access_token: accessToken, token_type: 'Bearer' });
      return;
    }
    this.send(res, 404, { error: 'not_found' });
  }

  private sign(payload: Record<string, unknown>): string {
    const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'test' }));
    const body = b64url(JSON.stringify(payload));
    const data = `${header}.${body}`;
    const signature = sign('RSA-SHA256', Buffer.from(data), this.privateKey);
    return `${data}.${b64url(signature)}`;
  }

  private send(res: ServerResponse, status: number, body: unknown): void {
    res.statusCode = status;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(body));
  }
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer | string) => {
      chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function authDouble() {
  return {
    validateApiKey: jest.fn((key: string) => {
      if (key !== 'programmatic-key') throw new UnauthorizedException('Invalid API key');
      return {
        id: 'key-1',
        name: 'Programmatic',
        keyHash: 'hash',
        keyPrefix: 'program',
        role: ApiKeyRole.ADMIN,
        allowedIps: null,
        allowedSessions: null,
        isActive: true,
        expiresAt: null,
        lastUsedAt: null,
        usageCount: 0,
        createdAt: new Date(),
        updatedAt: new Date(),
      } satisfies ApiKey;
    }),
    hasPermission: jest.fn((key: ApiKey, role: ApiKeyRole) => {
      const rank: Record<ApiKeyRole, number> = {
        [ApiKeyRole.VIEWER]: 1,
        [ApiKeyRole.OPERATOR]: 2,
        [ApiKeyRole.ADMIN]: 3,
      };
      return rank[key.role] >= rank[role];
    }),
  };
}

async function createApp(auth: ReturnType<typeof authDouble>): Promise<INestApplication<App>> {
  const moduleRef = await Test.createTestingModule({
    controllers: [SsoController, ProbeController],
    providers: [
      Reflector,
      SessionStore,
      SsoService,
      { provide: AuthService, useValue: auth },
      { provide: APP_GUARD, useClass: ApiKeyGuard },
    ],
  }).compile();
  const app = moduleRef.createNestApplication();
  app.setGlobalPrefix('api');
  await app.init();
  return app;
}

describe('SSO disabled', () => {
  let app: INestApplication<App>;

  beforeAll(async () => {
    delete process.env.OPENWA_SSO_ISSUER;
    delete process.env.OPENWA_SSO_CLIENT_ID;
    delete process.env.OPENWA_SSO_CLIENT_SECRET;
    delete process.env.OPENWA_SSO_REDIRECT_URL;
    app = await createApp(authDouble());
  });

  afterAll(async () => {
    await app?.close();
  });

  it('keeps the login endpoint dark and still accepts an API key', async () => {
    await request(app.getHttpServer()).get('/api/auth/sso/login').expect(404);

    const session = await request(app.getHttpServer()).get('/api/auth/sso/session').expect(200);
    expect(session.body).toEqual({ ssoEnabled: false, authenticated: false });

    await request(app.getHttpServer()).get('/api/probe').expect(401);
    await request(app.getHttpServer()).get('/api/probe').set('Cookie', 'openwa_session=stale').expect(401);

    const keyed = await request(app.getHttpServer()).get('/api/probe').set('X-API-Key', 'programmatic-key').expect(200);
    expect(keyed.body).toMatchObject({ ok: true, role: 'admin', name: 'Programmatic' });
  });
});

describe('SSO enabled', () => {
  const idp = new FakeKeycloak();
  const logs: string[] = [];
  let app: INestApplication<App>;
  const redirectUrl = 'https://openwa.example/api/auth/sso/callback';

  beforeAll(async () => {
    await idp.start();
    process.env.OPENWA_SSO_ISSUER = idp.issuer;
    process.env.OPENWA_SSO_CLIENT_ID = 'openwa';
    process.env.OPENWA_SSO_CLIENT_SECRET = idp.secret;
    process.env.OPENWA_SSO_REDIRECT_URL = redirectUrl;
    process.env.OPENWA_SSO_ROLE = 'openwa-user';
    process.env.OPENWA_SSO_COOKIE_SECURE = 'true';
    process.env.OPENWA_SSO_SESSION_TTL = '3600';
    app = await createApp(authDouble());
  });

  beforeEach(() => {
    idp.realmRoles = ['openwa-user'];
    idp.accessRoles = null;
    idp.nonce = '';
    idp.challenge = '';
  });

  afterAll(async () => {
    await app?.close();
    await idp.stop();
    delete process.env.OPENWA_SSO_ISSUER;
    delete process.env.OPENWA_SSO_CLIENT_ID;
    delete process.env.OPENWA_SSO_CLIENT_SECRET;
    delete process.env.OPENWA_SSO_REDIRECT_URL;
    delete process.env.OPENWA_SSO_ROLE;
    delete process.env.OPENWA_SSO_COOKIE_SECURE;
    delete process.env.OPENWA_SSO_SESSION_TTL;
  });

  async function startLogin() {
    const response = await request(app.getHttpServer()).get('/api/auth/sso/login').expect(302);
    const location = new URL(response.headers.location);
    idp.challenge = location.searchParams.get('code_challenge') || '';
    idp.nonce = location.searchParams.get('nonce') || '';
    return { response, location };
  }

  it('redirects to the IdP with PKCE and does not put the client secret in the browser URL', async () => {
    const { response, location } = await startLogin();
    expect(location.origin + location.pathname).toBe(`${idp.issuer}/protocol/openid-connect/auth`);
    expect(location.searchParams.get('response_type')).toBe('code');
    expect(location.searchParams.get('code_challenge_method')).toBe('S256');
    expect(location.searchParams.get('scope')).toContain('openid');
    expect(location.searchParams.get('state')).toBeTruthy();
    expect(location.searchParams.get('redirect_uri')).toBe(redirectUrl);
    expect(response.headers.location).not.toContain(idp.secret);
    const tx = cookieLines(response.headers['set-cookie']).find(line => line.startsWith('openwa_sso_tx='));
    expect(tx?.toLowerCase()).toContain('httponly');
    expect(tx?.toLowerCase()).toContain('samesite=lax');
    expect(tx?.toLowerCase()).toContain('secure');
    expect(cookieHeader([tx || ''])).toContain(`openwa_sso_tx=${location.searchParams.get('state')}`);
  });

  it('rejects a callback whose state does not match the transaction cookie', async () => {
    const { response, location } = await startLogin();
    const hits = idp.tokenHits;
    const rejected = await request(app.getHttpServer())
      .get('/api/auth/sso/callback')
      .query({ code: 'ok', state: 'not-the-state' })
      .set('Cookie', cookieHeader(cookieLines(response.headers['set-cookie'])))
      .expect(400);
    expect(rejected.text).toContain('invalid_state');
    expect(rejected.text).not.toContain(location.searchParams.get('nonce'));
    expect(idp.tokenHits).toBe(hits);
    expect(cookieLines(rejected.headers['set-cookie']).join(';')).not.toContain('openwa_session=');
  });

  it('rejects a callback when the ID token nonce does not match', async () => {
    const { response } = await startLogin();
    idp.nonce = 'wrong-nonce';
    const rejected = await request(app.getHttpServer())
      .get('/api/auth/sso/callback')
      .query({ code: 'ok', state: new URL(response.headers.location).searchParams.get('state') })
      .set('Cookie', cookieHeader(cookieLines(response.headers['set-cookie'])))
      .expect(400);
    expect(rejected.text).toContain('invalid_nonce');
    expect(cookieLines(rejected.headers['set-cookie']).join(';')).not.toContain('openwa_session=');
  });

  it('returns 403 and does not create a session when the required role is missing', async () => {
    const { response } = await startLogin();
    idp.realmRoles = ['offline_access'];
    idp.accessRoles = ['offline_access'];
    const denied = await request(app.getHttpServer())
      .get('/api/auth/sso/callback')
      .query({ code: 'ok', state: new URL(response.headers.location).searchParams.get('state') })
      .set('Cookie', cookieHeader(cookieLines(response.headers['set-cookie'])))
      .expect(403);
    expect(denied.text).toContain('role_denied');
    expect(cookieLines(denied.headers['set-cookie']).join(';')).not.toContain('openwa_session=');
  });

  it('accepts a role that is present only on the access token, then authorizes the API and still accepts an API key', async () => {
    const originalLog = console.log;
    const originalWarn = console.warn;
    console.log = (...args: unknown[]) => {
      logs.push(args.map(String).join(' '));
    };
    console.warn = (...args: unknown[]) => {
      logs.push(args.map(String).join(' '));
    };
    try {
      const { response } = await startLogin();
      idp.realmRoles = [];
      idp.accessRoles = ['openwa-user'];
      const state = new URL(response.headers.location).searchParams.get('state');
      const callback = await request(app.getHttpServer())
        .get('/api/auth/sso/callback')
        .query({ code: 'ok', state })
        .set('Cookie', cookieHeader(cookieLines(response.headers['set-cookie'])))
        .expect(302);
      expect(callback.headers.location).toBe('/');
      const sessionLine = cookieLines(callback.headers['set-cookie']).find(line => line.startsWith('openwa_session='));
      expect(sessionLine?.toLowerCase()).toContain('httponly');
      expect(sessionLine?.toLowerCase()).toContain('samesite=lax');
      expect(sessionLine?.toLowerCase()).toContain('secure');
      expect(sessionLine).not.toContain(idp.lastIdToken);

      const sessionCookie = cookieHeader([sessionLine || '']);
      const who = await request(app.getHttpServer())
        .get('/api/auth/sso/session')
        .set('Cookie', sessionCookie)
        .expect(200);
      expect(who.body).toEqual({ ssoEnabled: true, authenticated: true, role: 'admin', username: 'gabriel' });
      expect(JSON.stringify(who.body)).not.toContain(idp.lastIdToken);

      const probe = await request(app.getHttpServer()).get('/api/probe').set('Cookie', sessionCookie).expect(200);
      expect(probe.body).toEqual({ ok: true, role: 'admin', name: 'sso:gabriel' });

      const keyed = await request(app.getHttpServer())
        .get('/api/probe')
        .set('X-API-Key', 'programmatic-key')
        .expect(200);
      expect((keyed.body as { name: string }).name).toBe('Programmatic');

      const logout = await request(app.getHttpServer())
        .get('/api/auth/sso/logout')
        .set('Cookie', sessionCookie)
        .expect(302);
      expect(logout.headers.location).toContain('/protocol/openid-connect/logout');
      expect(logout.headers.location).toContain('post_logout_redirect_uri=');
      expect(logout.headers.location).not.toContain(idp.secret);

      await request(app.getHttpServer()).get('/api/probe').set('Cookie', sessionCookie).expect(401);
      expect(logs.join('\n')).not.toContain(idp.secret);
      expect(logs.join('\n')).not.toContain(idp.lastIdToken);
      expect(logs.join('\n')).not.toContain('openwa_session=');
    } finally {
      console.log = originalLog;
      console.warn = originalWarn;
    }
  });
});
