import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { parseTrustedProxies, resolveClientIp } from '../../../common/security/trusted-proxy';
import { AuthService } from '../auth.service';
import { ApiKey, ApiKeyRole } from '../entities/api-key.entity';
import { REQUIRED_ROLE_KEY, PUBLIC_KEY } from '../decorators/auth.decorators';
import { resolveSessionAuth } from '../sso/sso-principal';
import { SessionStore } from '../sso/session-store';

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(
    private readonly authService: AuthService,
    private readonly reflector: Reflector,
    private readonly sessions: SessionStore,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(PUBLIC_KEY, [context.getHandler(), context.getClass()]);

    if (isPublic) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();
    const apiKeyHeader = this.extractApiKey(request);
    const sessionId = (request.params['sessionId'] || request.params['id']) as string | undefined;
    const clientIp = this.getClientIp(request);

    if (apiKeyHeader) {
      const apiKey = await this.authService.validateApiKey(apiKeyHeader, clientIp, sessionId);
      this.assertRole(apiKey, context);
      (request as Request & { apiKey: typeof apiKey }).apiKey = apiKey;
      return true;
    }

    const sessionAuth = resolveSessionAuth(this.sessions, request.headers.cookie);
    switch (sessionAuth.status) {
      case 'ok': {
        this.assertRole(sessionAuth.apiKey, context);
        (request as Request & { apiKey: typeof sessionAuth.apiKey }).apiKey = sessionAuth.apiKey;
        return true;
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

  private assertRole(apiKey: ApiKey, context: ExecutionContext): void {
    const requiredRole = this.reflector.getAllAndOverride<ApiKeyRole>(REQUIRED_ROLE_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (requiredRole && !this.authService.hasPermission(apiKey, requiredRole)) {
      throw new UnauthorizedException(`Insufficient permissions. Required: ${requiredRole}`);
    }
  }

  private extractApiKey(request: Request): string | undefined {
    const xApiKey = request.headers['x-api-key'] as string;
    if (xApiKey) return xApiKey;

    const authHeader = request.headers['authorization'];
    if (authHeader?.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }

    return undefined;
  }

  private getClientIp(request: Request): string {
    return resolveClientIp(request, parseTrustedProxies(process.env.OPENWA_TRUST_PROXY));
  }
}
