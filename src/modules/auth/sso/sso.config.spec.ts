import { DEFAULT_SESSION_TTL_SECONDS, DEFAULT_SSO_ROLE, loadSsoConfig } from './sso.config';

describe('loadSsoConfig', () => {
  it('stays disabled unless issuer, client id, and redirect URL are all set', () => {
    expect(loadSsoConfig({}).enabled).toBe(false);
    expect(
      loadSsoConfig({
        OPENWA_SSO_ISSUER: 'https://idp.example/realms/MartinsTech',
        OPENWA_SSO_CLIENT_ID: 'openwa',
      }).enabled,
    ).toBe(false);
  });

  it('enables SSO and applies defaults when the three required values are present', () => {
    const config = loadSsoConfig({
      OPENWA_SSO_ISSUER: 'https://idp.example/realms/MartinsTech/',
      OPENWA_SSO_CLIENT_ID: 'openwa',
      OPENWA_SSO_REDIRECT_URL: 'https://openwa.example/api/auth/sso/callback',
      OPENWA_SSO_CLIENT_SECRET: '   ',
    });

    expect(config.enabled).toBe(true);
    expect(config.issuer).toBe('https://idp.example/realms/MartinsTech');
    expect(config.clientSecret).toBeUndefined();
    expect(config.role).toBe(DEFAULT_SSO_ROLE);
    expect(config.sessionTtlSeconds).toBe(DEFAULT_SESSION_TTL_SECONDS);
    expect(config.cookieSecure).toBe(false);
    expect(config.postLogoutUrl).toBe('https://openwa.example/');
  });

  it('honors role, ttl, secret, secure cookie, and post-logout overrides', () => {
    const config = loadSsoConfig({
      NODE_ENV: 'production',
      OPENWA_SSO_ISSUER: 'https://idp.example/realms/MartinsTech',
      OPENWA_SSO_CLIENT_ID: 'openwa',
      OPENWA_SSO_CLIENT_SECRET: 'super-secret',
      OPENWA_SSO_REDIRECT_URL: 'https://openwa.example/api/auth/sso/callback',
      OPENWA_SSO_ROLE: 'openwa-admin',
      OPENWA_SSO_SESSION_TTL: '7200',
      OPENWA_SSO_COOKIE_SECURE: 'false',
      OPENWA_SSO_POST_LOGOUT_URL: 'https://openwa.example/logged-out',
    });

    expect(config.clientSecret).toBe('super-secret');
    expect(config.role).toBe('openwa-admin');
    expect(config.sessionTtlSeconds).toBe(7200);
    expect(config.cookieSecure).toBe(false);
    expect(config.postLogoutUrl).toBe('https://openwa.example/logged-out');
  });

  it('defaults the session cookie to Secure in production', () => {
    const config = loadSsoConfig({
      NODE_ENV: 'production',
      OPENWA_SSO_ISSUER: 'https://idp.example/realms/MartinsTech',
      OPENWA_SSO_CLIENT_ID: 'openwa',
      OPENWA_SSO_REDIRECT_URL: 'https://openwa.example/api/auth/sso/callback',
    });
    expect(config.cookieSecure).toBe(true);
  });

  it('refuses a non-HTTP post-logout URL', () => {
    const config = loadSsoConfig({
      OPENWA_SSO_ISSUER: 'https://idp.example/realms/MartinsTech',
      OPENWA_SSO_CLIENT_ID: 'openwa',
      OPENWA_SSO_REDIRECT_URL: 'https://openwa.example/api/auth/sso/callback',
      OPENWA_SSO_POST_LOGOUT_URL: 'javascript:alert(1)',
    });
    expect(config.postLogoutUrl).toBe('/');
  });

  it('falls back when the session TTL is not a usable number', () => {
    const config = loadSsoConfig({
      OPENWA_SSO_ISSUER: 'https://idp.example/realms/MartinsTech',
      OPENWA_SSO_CLIENT_ID: 'openwa',
      OPENWA_SSO_REDIRECT_URL: 'https://openwa.example/api/auth/sso/callback',
      OPENWA_SSO_SESSION_TTL: 'nope',
    });
    expect(config.sessionTtlSeconds).toBe(DEFAULT_SESSION_TTL_SECONDS);
  });
});
