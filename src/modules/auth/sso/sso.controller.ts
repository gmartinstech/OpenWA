import { Controller, Get, HttpException, Post, Req, Res } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Request, Response } from 'express';
import { Public, RequireUnscopedKey } from '../decorators/auth.decorators';
import { loadSsoConfig, type SessionCookieOptions } from './sso.config';
import { readCookie } from './sso-principal';
import { SsoFlowError, SsoService, type SsoFailureReason } from './sso.service';

@ApiTags('auth')
@Controller('auth/sso')
export class SsoController {
  constructor(private readonly sso: SsoService) {}

  @Get('session')
  @Public()
  @ApiOperation({ summary: 'Whether dashboard SSO is enabled and the browser has a session' })
  session(@Req() req: Request) {
    return this.sso.describeSession(req.headers.cookie);
  }

  @Get('login')
  @Public()
  @ApiOperation({ summary: 'Start the Keycloak authorization code + PKCE login' })
  async login(@Res() res: Response): Promise<void> {
    try {
      const started = await this.sso.beginLogin();
      res.cookie(started.txCookie.name, started.txCookie.value, started.txCookie.options);
      res.redirect(302, started.location);
    } catch (error) {
      this.sendError(res, error);
    }
  }

  @Get('callback')
  @Public()
  @ApiOperation({ summary: 'Complete the Keycloak login and set the dashboard session cookie' })
  async callback(@Req() req: Request, @Res() res: Response): Promise<void> {
    const config = loadSsoConfig();
    const query = req.query as Record<string, unknown>;
    try {
      const completed = await this.sso.completeLogin({
        code: single(query.code),
        state: single(query.state),
        txCookie: readCookie(req.headers.cookie, config.txCookieName),
      });
      clearCookie(res, config.txCookieName, { ...completed.cookie.options, path: '/api/auth/sso', maxAge: undefined });
      res.cookie(completed.cookie.name, completed.cookie.value, completed.cookie.options);
      res.redirect(302, completed.location);
    } catch (error) {
      clearCookie(res, config.txCookieName, txClearOptions());
      this.sendError(res, error);
    }
  }

  @Post('logout')
  @RequireUnscopedKey()
  @ApiOperation({ summary: 'Clear the dashboard session. Requires the session cookie and CSRF header.' })
  async logout(@Req() req: Request, @Res() res: Response): Promise<void> {
    const config = loadSsoConfig();
    const location = await this.sso.logout(req.headers.cookie);
    clearCookie(res, config.sessionCookieName, {
      httpOnly: true,
      sameSite: 'lax',
      secure: config.cookieSecure,
      path: '/',
    });
    // JSON, not a 302: a cross-site form cannot both present the Lax cookie and read this body.
    // The dashboard navigates to logoutUrl itself.
    res.status(200).json({ logoutUrl: location });
  }

  private sendError(res: Response, error: unknown): void {
    if (error instanceof SsoFlowError) {
      res.status(statusFor(error.reason)).type('html').send(errorPage(error.reason));
      return;
    }
    if (error instanceof HttpException) {
      const status = error.getStatus();
      const body = error.getResponse();
      const message = typeof body === 'string' ? body : messageOf(body);
      res.status(status).json({ message });
      return;
    }
    res.status(500).json({ message: 'SSO login failed' });
  }
}

function single(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function messageOf(body: unknown): string {
  if (typeof body === 'object' && body !== null && 'message' in body) {
    const message = body.message;
    if (typeof message === 'string') return message;
    if (Array.isArray(message) && typeof message[0] === 'string') return message[0];
  }
  return 'SSO login failed';
}

function txClearOptions(): SessionCookieOptions {
  const config = loadSsoConfig();
  return { httpOnly: true, sameSite: 'lax', secure: config.cookieSecure, path: '/api/auth/sso' };
}

function clearCookie(res: Response, name: string, options: SessionCookieOptions): void {
  res.clearCookie(name, options);
}

function statusFor(reason: SsoFailureReason): number {
  switch (reason) {
    case 'role_denied':
      return 403;
    case 'upstream':
      return 502;
    case 'invalid_state':
    case 'invalid_nonce':
    case 'invalid_token':
      return 400;
    default: {
      const exhaustive: never = reason;
      return exhaustive;
    }
  }
}

function errorPage(reason: SsoFailureReason): string {
  const copy: Record<SsoFailureReason, string> = {
    invalid_state: 'O login expirou ou foi iniciado em outro navegador. Tente novamente.',
    invalid_nonce: 'A resposta do provedor de identidade não pôde ser confirmada. Tente novamente.',
    invalid_token: 'A resposta do provedor de identidade foi rejeitada. Tente novamente.',
    role_denied: 'Acesso negado. A conta não possui o papel exigido para o OpenWA.',
    upstream: 'O provedor de identidade está indisponível. Tente novamente.',
  };
  return `<!doctype html><html lang="pt"><head><meta charset="utf-8"><title>OpenWA</title></head><body><p>${copy[reason]}</p><p id="sso-error">${reason}</p><p><a href="/">Voltar</a></p></body></html>`;
}
