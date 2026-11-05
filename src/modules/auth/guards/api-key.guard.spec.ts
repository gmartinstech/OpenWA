import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ApiKeyGuard } from './api-key.guard';
import { AuthService } from '../auth.service';
import { ApiKey, ApiKeyRole } from '../entities/api-key.entity';
import { SessionStore } from '../sso/session-store';

function createMockApiKey(overrides: Partial<ApiKey> = {}): ApiKey {
  return {
    id: 'uuid-1',
    name: 'Test Key',
    keyHash: 'hash',
    keyPrefix: 'owa_k1_xxxx',
    role: ApiKeyRole.OPERATOR,
    allowedIps: null,
    allowedSessions: null,
    isActive: true,
    expiresAt: null,
    lastUsedAt: null,
    usageCount: 0,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };
}

function createMockContext(
  headers: Record<string, string> = {},
  params: Record<string, string> = {},
): ExecutionContext {
  const request = {
    headers,
    params,
    ip: '127.0.0.1',
    socket: { remoteAddress: '127.0.0.1' },
  };

  return {
    switchToHttp: () => ({
      getRequest: () => request,
    }),
    getHandler: () => ({}),
    getClass: () => ({}),
  } as unknown as ExecutionContext;
}

describe('ApiKeyGuard', () => {
  let guard: ApiKeyGuard;
  let authService: jest.Mocked<Partial<AuthService>>;
  let reflector: jest.Mocked<Reflector>;
  let sessions: SessionStore;

  beforeEach(() => {
    delete process.env.OPENWA_TRUST_PROXY;
    delete process.env.OPENWA_SSO_ISSUER;
    delete process.env.OPENWA_SSO_CLIENT_ID;
    delete process.env.OPENWA_SSO_REDIRECT_URL;

    authService = {
      validateApiKey: jest.fn(),
      hasPermission: jest.fn(),
    };

    reflector = {
      getAllAndOverride: jest.fn(),
    } as unknown as jest.Mocked<Reflector>;

    sessions = new SessionStore();
    guard = new ApiKeyGuard(authService as AuthService, reflector, sessions);
  });

  it('should allow access to @Public() routes without API key', async () => {
    reflector.getAllAndOverride.mockReturnValueOnce(true); // isPublic = true

    const context = createMockContext();
    const result = await guard.canActivate(context);

    expect(result).toBe(true);
    expect(authService.validateApiKey).not.toHaveBeenCalled();
  });

  it('should reject requests without X-API-Key header', async () => {
    reflector.getAllAndOverride.mockReturnValueOnce(false); // not public

    const context = createMockContext({});

    await expect(guard.canActivate(context)).rejects.toThrow(UnauthorizedException);
    await expect(guard.canActivate(context)).rejects.toThrow('API key is required');
  });

  it('should accept X-API-Key header', async () => {
    reflector.getAllAndOverride
      .mockReturnValueOnce(false) // not public
      .mockReturnValueOnce(undefined); // no required role

    const apiKey = createMockApiKey();
    (authService.validateApiKey as jest.Mock).mockResolvedValue(apiKey);

    const context = createMockContext({ 'x-api-key': 'my-key' });
    const result = await guard.canActivate(context);

    expect(result).toBe(true);
    expect(authService.validateApiKey).toHaveBeenCalledWith('my-key', '127.0.0.1', undefined);
  });

  it('should accept Authorization Bearer header', async () => {
    reflector.getAllAndOverride.mockReturnValueOnce(false).mockReturnValueOnce(undefined);

    const apiKey = createMockApiKey();
    (authService.validateApiKey as jest.Mock).mockResolvedValue(apiKey);

    const context = createMockContext({ authorization: 'Bearer my-bearer-key' });
    const result = await guard.canActivate(context);

    expect(result).toBe(true);
    expect(authService.validateApiKey).toHaveBeenCalledWith('my-bearer-key', '127.0.0.1', undefined);
  });

  it('should reject when API key validation fails', async () => {
    reflector.getAllAndOverride.mockReturnValueOnce(false);

    (authService.validateApiKey as jest.Mock).mockRejectedValue(new UnauthorizedException('Invalid API key'));

    const context = createMockContext({ 'x-api-key': 'bad-key' });

    await expect(guard.canActivate(context)).rejects.toThrow('Invalid API key');
  });

  it('should reject when role permission is insufficient', async () => {
    reflector.getAllAndOverride
      .mockReturnValueOnce(false) // not public
      .mockReturnValueOnce(ApiKeyRole.ADMIN); // required role = ADMIN

    const apiKey = createMockApiKey({ role: ApiKeyRole.VIEWER });
    (authService.validateApiKey as jest.Mock).mockResolvedValue(apiKey);
    (authService.hasPermission as jest.Mock).mockReturnValue(false);

    const context = createMockContext({ 'x-api-key': 'viewer-key' });

    await expect(guard.canActivate(context)).rejects.toThrow('Insufficient permissions');
  });

  it('should pass session ID from route params to validateApiKey', async () => {
    reflector.getAllAndOverride.mockReturnValueOnce(false).mockReturnValueOnce(undefined);

    const apiKey = createMockApiKey();
    (authService.validateApiKey as jest.Mock).mockResolvedValue(apiKey);

    const context = createMockContext({ 'x-api-key': 'key' }, { sessionId: 'sess-123' });
    await guard.canActivate(context);

    expect(authService.validateApiKey).toHaveBeenCalledWith('key', '127.0.0.1', 'sess-123');
  });

  it('ignores X-Forwarded-For when the peer is not a trusted proxy', async () => {
    reflector.getAllAndOverride.mockReturnValueOnce(false).mockReturnValueOnce(undefined);

    const apiKey = createMockApiKey();
    (authService.validateApiKey as jest.Mock).mockResolvedValue(apiKey);

    const context = createMockContext({
      'x-api-key': 'key',
      'x-forwarded-for': '203.0.113.50, 70.41.3.18',
    });
    await guard.canActivate(context);

    expect(authService.validateApiKey).toHaveBeenCalledWith('key', '127.0.0.1', undefined);
  });

  it('reads X-Forwarded-For when the TCP peer is a trusted proxy', async () => {
    process.env.OPENWA_TRUST_PROXY = '127.0.0.1';
    reflector.getAllAndOverride.mockReturnValueOnce(false).mockReturnValueOnce(undefined);

    const apiKey = createMockApiKey();
    (authService.validateApiKey as jest.Mock).mockResolvedValue(apiKey);

    const context = createMockContext({
      'x-api-key': 'key',
      'x-forwarded-for': '203.0.113.50, 70.41.3.18',
    });
    await guard.canActivate(context);

    expect(authService.validateApiKey).toHaveBeenCalledWith('key', '203.0.113.50', undefined);
  });

  it('accepts a live SSO session cookie with the same admin authorization as an API key', async () => {
    process.env.OPENWA_SSO_ISSUER = 'https://idp.example/realms/MartinsTech';
    process.env.OPENWA_SSO_CLIENT_ID = 'openwa';
    process.env.OPENWA_SSO_REDIRECT_URL = 'https://openwa.example/api/auth/sso/callback';
    reflector.getAllAndOverride.mockReturnValueOnce(false).mockReturnValueOnce(ApiKeyRole.ADMIN);
    (authService.hasPermission as jest.Mock).mockReturnValue(true);

    const session = sessions.createSession({
      subject: 'sub-1',
      username: 'gabriel',
      idToken: 'do-not-log',
      ttlSeconds: 60,
    });
    const request: {
      headers: Record<string, string>;
      params: Record<string, string>;
      ip: string;
      socket: { remoteAddress: string };
      apiKey?: ApiKey;
    } = {
      headers: { cookie: `openwa_session=${session!.id}` },
      params: {},
      ip: '127.0.0.1',
      socket: { remoteAddress: '127.0.0.1' },
    };
    const context = {
      switchToHttp: () => ({ getRequest: () => request }),
      getHandler: () => ({}),
      getClass: () => ({}),
    } as unknown as ExecutionContext;

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(authService.validateApiKey).not.toHaveBeenCalled();
    expect(request.apiKey?.role).toBe(ApiKeyRole.ADMIN);
    expect(request.apiKey?.name).toBe('sso:gabriel');
  });

  it('rejects an expired SSO session without falling through to a missing API key message', async () => {
    process.env.OPENWA_SSO_ISSUER = 'https://idp.example/realms/MartinsTech';
    process.env.OPENWA_SSO_CLIENT_ID = 'openwa';
    process.env.OPENWA_SSO_REDIRECT_URL = 'https://openwa.example/api/auth/sso/callback';
    reflector.getAllAndOverride.mockReturnValueOnce(false);

    const session = sessions.createSession({
      subject: 'sub-1',
      username: 'gabriel',
      idToken: 'do-not-log',
      ttlSeconds: 0,
    });
    const context = createMockContext({ cookie: `openwa_session=${session!.id}` });

    await expect(guard.canActivate(context)).rejects.toThrow('Session expired');
  });

  it('ignores a session cookie when SSO is disabled', async () => {
    reflector.getAllAndOverride.mockReturnValueOnce(false);
    const context = createMockContext({ cookie: 'openwa_session=whatever' });
    await expect(guard.canActivate(context)).rejects.toThrow('API key is required');
  });

  it('does not fall back to a session cookie when the API key is invalid', async () => {
    process.env.OPENWA_SSO_ISSUER = 'https://idp.example/realms/MartinsTech';
    process.env.OPENWA_SSO_CLIENT_ID = 'openwa';
    process.env.OPENWA_SSO_REDIRECT_URL = 'https://openwa.example/api/auth/sso/callback';
    reflector.getAllAndOverride.mockReturnValueOnce(false);
    (authService.validateApiKey as jest.Mock).mockRejectedValue(new UnauthorizedException('Invalid API key'));
    const session = sessions.createSession({
      subject: 'sub-1',
      username: 'gabriel',
      idToken: 'do-not-log',
      ttlSeconds: 60,
    });
    const context = createMockContext({
      'x-api-key': 'bad-key',
      cookie: `openwa_session=${session!.id}`,
    });

    await expect(guard.canActivate(context)).rejects.toThrow('Invalid API key');
  });
});
