import { Injectable, NotFoundException } from '@nestjs/common';
import { createLogger } from '../../../common/services/logger.service';
import {
  DiscoveryError,
  JwtError,
  collectRoles,
  exchangeAuthorizationCode,
  fetchDiscovery,
  fetchJwks,
  randomToken,
  safeEqual,
  verifyJwt,
  createPkce,
  type JsonWebKeyWithKid,
  type OidcDiscovery,
  type VerifiedClaims,
} from './oidc';
import {
  SSO_TX_TTL_SECONDS,
  loadSsoConfig,
  sessionCookieOptions,
  txCookieOptions,
  type SessionCookieOptions,
  type SsoConfig,
} from './sso.config';
import { readCookie } from './sso-principal';
import { SessionStore } from './session-store';

export type SsoFailureReason = 'invalid_state' | 'invalid_nonce' | 'invalid_token' | 'role_denied' | 'upstream';

export class SsoFlowError extends Error {
  constructor(readonly reason: SsoFailureReason) {
    super(reason);
  }
}

export interface LoginStart {
  location: string;
  txCookie: { name: string; value: string; options: SessionCookieOptions };
}

@Injectable()
export class SsoService {
  private readonly logger = createLogger('SsoService');
  private discoveryCache: { issuer: string; document: OidcDiscovery; fetchedAt: number } | null = null;
  private jwksCache: { url: string; keys: JsonWebKeyWithKid[]; fetchedAt: number } | null = null;

  constructor(private readonly store: SessionStore) {}

  private get fetchImpl(): typeof fetch {
    return globalThis.fetch.bind(globalThis);
  }

  describeSession(cookieHeader: string | undefined): {
    ssoEnabled: boolean;
    authenticated: boolean;
    role?: 'admin';
    username?: string;
  } {
    const config = loadSsoConfig();
    if (!config.enabled) return { ssoEnabled: false, authenticated: false };
    const sessionId = readCookie(cookieHeader, config.sessionCookieName);
    if (!sessionId) return { ssoEnabled: true, authenticated: false };
    const session = this.store.getSession(sessionId);
    if (!session) return { ssoEnabled: true, authenticated: false };
    return { ssoEnabled: true, authenticated: true, role: 'admin', username: session.username };
  }

  async beginLogin(): Promise<LoginStart> {
    const config = this.requireEnabled();
    const discovery = await this.discoveryOrThrow(config);
    const pkce = createPkce();
    const state = randomToken();
    const nonce = randomToken();
    const stored = this.store.putPending({
      state,
      nonce,
      codeVerifier: pkce.verifier,
      expiresAt: Date.now() + SSO_TX_TTL_SECONDS * 1000,
    });
    if (!stored) throw new SsoFlowError('upstream');

    const url = new URL(discovery.authorization_endpoint);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', config.clientId);
    url.searchParams.set('redirect_uri', config.redirectUrl);
    url.searchParams.set('scope', 'openid profile');
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set('code_challenge', pkce.challenge);
    url.searchParams.set('code_challenge_method', 'S256');

    this.logger.log('SSO login started');
    return {
      location: url.toString(),
      txCookie: { name: config.txCookieName, value: state, options: txCookieOptions(config) },
    };
  }

  async completeLogin(input: { code?: string; state?: string; txCookie?: string }): Promise<{
    location: string;
    sessionId: string;
    cookie: { name: string; value: string; options: SessionCookieOptions };
  }> {
    const config = this.requireEnabled();
    if (!input.code || !input.state || !input.txCookie || !safeEqual(input.state, input.txCookie)) {
      this.reject('invalid_state');
    }
    const pending = this.store.takePending(input.state);
    if (!pending) this.reject('invalid_state');

    try {
      const discovery = await this.discoveryOrThrow(config);
      const tokens = await exchangeAuthorizationCode(
        {
          tokenEndpoint: discovery.token_endpoint,
          code: input.code,
          redirectUri: config.redirectUrl,
          clientId: config.clientId,
          codeVerifier: pending.codeVerifier,
          clientSecret: config.clientSecret,
        },
        this.fetchImpl,
      );
      const idClaims = await this.verifyWithRefresh(tokens.idToken, discovery.jwks_uri, {
        issuer: config.issuer,
        audience: config.clientId,
        nonce: pending.nonce,
      });
      const roles = [...collectRoles(idClaims.raw, config.clientId)];
      if (tokens.accessToken && tokens.accessToken.split('.').length === 3) {
        const accessClaims = await this.verifyWithRefresh(tokens.accessToken, discovery.jwks_uri, {
          issuer: config.issuer,
          audience: config.clientId,
          accessToken: true,
        });
        roles.push(...collectRoles(accessClaims.raw, config.clientId));
      }
      if (!roles.includes(config.role)) this.reject('role_denied');

      const session = this.store.createSession({
        subject: idClaims.sub,
        username: usernameFrom(idClaims),
        idToken: tokens.idToken,
        ttlSeconds: config.sessionTtlSeconds,
      });
      if (!session) this.reject('upstream');
      this.logger.log('SSO session created');
      return {
        location: '/',
        sessionId: session.id,
        cookie: { name: config.sessionCookieName, value: session.id, options: sessionCookieOptions(config) },
      };
    } catch (error) {
      if (error instanceof SsoFlowError) throw error;
      if (error instanceof JwtError && error.reason === 'nonce') this.reject('invalid_nonce');
      if (error instanceof DiscoveryError) this.reject('upstream');
      this.reject('invalid_token');
    }
  }

  async logout(cookieHeader: string | undefined): Promise<string> {
    const config = loadSsoConfig();
    const sessionId = config.enabled ? readCookie(cookieHeader, config.sessionCookieName) : undefined;
    const session = sessionId ? this.store.deleteSession(sessionId) : undefined;
    if (!config.enabled) return '/';
    try {
      const discovery = await this.discoveryOrThrow(config);
      if (!discovery.end_session_endpoint) return config.postLogoutUrl;
      const url = new URL(discovery.end_session_endpoint);
      url.searchParams.set('client_id', config.clientId);
      url.searchParams.set('post_logout_redirect_uri', config.postLogoutUrl);
      if (session?.idToken) url.searchParams.set('id_token_hint', session.idToken);
      this.logger.log('SSO session cleared');
      return url.toString();
    } catch {
      this.logger.warn('SSO logout fell back to local redirect');
      return config.postLogoutUrl;
    }
  }

  private requireEnabled(): SsoConfig {
    const config = loadSsoConfig();
    if (!config.enabled) throw new NotFoundException('SSO is disabled');
    return config;
  }

  private reject(reason: SsoFailureReason): never {
    this.logger.warn('SSO login rejected', { reason });
    throw new SsoFlowError(reason);
  }

  private async discoveryOrThrow(config: SsoConfig): Promise<OidcDiscovery> {
    const freshFor = 5 * 60 * 1000;
    if (
      this.discoveryCache &&
      this.discoveryCache.issuer === config.issuer &&
      Date.now() - this.discoveryCache.fetchedAt < freshFor
    ) {
      return this.discoveryCache.document;
    }
    try {
      const document = await fetchDiscovery(config.issuer, this.fetchImpl);
      this.discoveryCache = { issuer: config.issuer, document, fetchedAt: Date.now() };
      return document;
    } catch (error) {
      if (error instanceof DiscoveryError) throw error;
      throw new DiscoveryError();
    }
  }

  private async keysFor(jwksUri: string, force: boolean): Promise<JsonWebKeyWithKid[]> {
    const freshFor = 10 * 60 * 1000;
    if (
      !force &&
      this.jwksCache &&
      this.jwksCache.url === jwksUri &&
      Date.now() - this.jwksCache.fetchedAt < freshFor
    ) {
      return this.jwksCache.keys;
    }
    const keys = await fetchJwks(jwksUri, this.fetchImpl);
    this.jwksCache = { url: jwksUri, keys, fetchedAt: Date.now() };
    return keys;
  }

  private async verifyWithRefresh(
    token: string,
    jwksUri: string,
    options: { issuer: string; audience: string; nonce?: string; accessToken?: boolean },
  ): Promise<VerifiedClaims> {
    try {
      return verifyJwt(token, await this.keysFor(jwksUri, false), options);
    } catch (error) {
      if (error instanceof JwtError && error.reason === 'unknown_kid') {
        return verifyJwt(token, await this.keysFor(jwksUri, true), options);
      }
      throw error;
    }
  }
}

function usernameFrom(claims: VerifiedClaims): string {
  const preferred = claims.preferred_username?.trim();
  if (preferred) return preferred.slice(0, 80);
  return claims.sub.slice(0, 80);
}
