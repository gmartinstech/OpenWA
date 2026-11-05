import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { AuthService } from '../auth.service';
import { ApiKey, ApiKeyRole } from '../entities/api-key.entity';
import { REQUIRED_ROLE_KEY, PUBLIC_KEY, SESSION_SCOPED_KEY, UNSCOPED_KEY } from '../decorators/auth.decorators';
import { resolveClientIp } from '../../../common/utils/ip';
import { setRequestActor } from '../../../common/services/request-context';
import { AuditService } from '../../audit/audit.service';
import { AuditAction } from '../../audit/entities/audit-log.entity';
import { SessionStore } from '../sso/session-store';
import { csrfHeaderMatches, isSafeHttpMethod, resolveSessionAuth } from '../sso/sso-principal';

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(
    private readonly authService: AuthService,
    private readonly reflector: Reflector,
    private readonly configService: ConfigService,
    private readonly auditService: AuditService,
    private readonly sessions: SessionStore = new SessionStore(),
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Check if route is marked as public
    const isPublic = this.reflector.getAllAndOverride<boolean>(PUBLIC_KEY, [context.getHandler(), context.getClass()]);

    if (isPublic) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();
    try {
      return await this.authorize(request, context);
    } catch (err) {
      // Record rejected/denied authentication attempts so the audit log has a forensic trail for
      // credential probing. Fire-and-forget: audit logging is best-effort and must never turn a
      // 401/403 into a failure of the guard itself.
      if (err instanceof UnauthorizedException || err instanceof ForbiddenException) {
        // Stamp at least the IP so the failed-auth audit row below is attributable even though the
        // key was never resolved. setRequestActor is a no-op outside a request scope.
        setRequestActor({ ipAddress: this.getClientIp(request) });
        void this.auditService.logWarn(AuditAction.API_KEY_AUTH_FAILED, {
          ipAddress: this.getClientIp(request),
          method: request.method,
          path: request.path,
          errorMessage: err.message,
        });
      }
      throw err;
    }
  }

  private async authorize(request: Request, context: ExecutionContext): Promise<boolean> {
    const apiKeyHeader = this.extractApiKey(request);
    const clientIp = this.getClientIp(request);

    if (!apiKeyHeader) {
      return this.authorizeSession(request, context, clientIp);
    }

    // Resolve the session id used for the key's allowedSessions scope. `:sessionId` is always a
    // session; the bare `:id` param is only a session on controllers marked @SessionScoped (i.e.
    // SessionController) — on other routes `:id` is an unrelated resource id (API key, plugin, …)
    // and must NOT be fed to the allowedSessions check, which would spuriously deny a scoped key.
    const requiredRole = this.reflector.getAllAndOverride<ApiKeyRole>(REQUIRED_ROLE_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    const sessionScoped = this.reflector.getAllAndOverride<boolean>(SESSION_SCOPED_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    const sessionId = (request.params['sessionId'] || (sessionScoped ? request.params['id'] : undefined)) as
      string | undefined;

    // Validate API key. A presented key is never replaced by a session cookie.
    const apiKey = await this.authService.validateApiKey(apiKeyHeader, clientIp, sessionId);
    if (requiredRole && !this.authService.hasPermission(apiKey, requiredRole)) {
      throw new ForbiddenException(`Insufficient permissions. Required: ${requiredRole}`);
    }
    return this.attachPrincipal(request, context, apiKey, clientIp);
  }

  private authorizeSession(request: Request, context: ExecutionContext, clientIp: string): boolean {
    const sessionAuth = resolveSessionAuth(this.sessions, request.headers.cookie);
    switch (sessionAuth.status) {
      case 'ok': {
        // Cookie auth on an unsafe method needs the per-session CSRF secret. SameSite=Lax does
        // not cover a same-site subresource or a browser that still sends the cookie on POST.
        if (
          !isSafeHttpMethod(request.method) &&
          !csrfHeaderMatches(request.headers['x-csrf-token'], sessionAuth.csrfToken)
        ) {
          throw new ForbiddenException('CSRF token rejected');
        }
        return this.finishAuthorized(request, context, sessionAuth.apiKey, clientIp);
      }
      case 'expired':
        throw new UnauthorizedException('Session expired');
      case 'absent':
      case 'disabled':
        throw new UnauthorizedException('API key is required');
      default: {
        const exhaustive: never = sessionAuth;
        return exhaustive;
      }
    }
  }

  private finishAuthorized(request: Request, context: ExecutionContext, apiKey: ApiKey, clientIp: string): boolean {
    const requiredRole = this.reflector.getAllAndOverride<ApiKeyRole>(REQUIRED_ROLE_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (requiredRole && !this.authService.hasPermission(apiKey, requiredRole)) {
      throw new ForbiddenException(`Insufficient permissions. Required: ${requiredRole}`);
    }
    return this.attachPrincipal(request, context, apiKey, clientIp);
  }

  private attachPrincipal(request: Request, context: ExecutionContext, apiKey: ApiKey, clientIp: string): boolean {
    // Routes marked @RequireUnscopedKey carry no session dimension, so the allowedSessions check
    // above can never bite on them. A session-scoped key reaching such a surface (e.g. API-key
    // lifecycle management) could mint or widen credentials beyond its own confinement — reject it
    // outright, whatever its role. The denial is audited by the caller's catch block.
    const requireUnscoped = this.reflector.getAllAndOverride<boolean>(UNSCOPED_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (requireUnscoped && (apiKey.allowedSessions?.length ?? 0) > 0) {
      throw new ForbiddenException('Session-scoped API keys are not permitted on this route');
    }

    // Attach API key to request for use in controllers
    (request as Request & { apiKey: typeof apiKey }).apiKey = apiKey;
    // Expose the trusted-proxy-aware client IP so controllers (e.g. the audit trail on key lifecycle
    // ops) reuse the already-resolved value instead of re-deriving it.
    (request as Request & { clientIp?: string }).clientIp = clientIp;

    // Stamp the resolved actor into the per-request async context so downstream audit log writes —
    // which fire from services deep in the call stack without DI access to the key — can attribute
    // the action to this key + IP. Without this every audit row's apiKey/ipAddress column is blank
    // because call sites pass only { sessionId } etc.
    setRequestActor({ apiKeyId: apiKey.id, apiKeyName: apiKey.name, ipAddress: clientIp });

    return true;
  }

  private extractApiKey(request: Request): string | undefined {
    // Support both X-API-Key header and Authorization Bearer
    const xApiKey = request.headers['x-api-key'] as string;
    if (xApiKey) return xApiKey;

    const authHeader = request.headers['authorization'];
    if (authHeader?.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }

    return undefined;
  }

  /**
   * Resolve the real client IP used for the API key's allowedIps whitelist.
   *
   * X-Forwarded-For is client-controllable, so it is only honored when the
   * request actually arrives from a configured trusted proxy (TRUSTED_PROXIES).
   * With no trusted proxies configured, the header is ignored entirely and the
   * direct socket address is used — preventing IP-whitelist spoofing.
   */
  private getClientIp(request: Request): string {
    const trustedProxies = this.configService.get<string[]>('security.trustedProxies') ?? [];
    return resolveClientIp(request, trustedProxies);
  }
}
