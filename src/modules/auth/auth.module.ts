import { Module, Global } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard } from '@nestjs/throttler';
import { ApiKey } from './entities/api-key.entity';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { AuthValidateController } from './auth-validate.controller';
import { ApiKeyGuard } from './guards/api-key.guard';
import { SessionStore } from './sso/session-store';
import { SsoService } from './sso/sso.service';
import { SsoController } from './sso/sso.controller';

@Global()
@Module({
  imports: [TypeOrmModule.forFeature([ApiKey], 'main')],
  controllers: [AuthController, AuthValidateController, SsoController],
  providers: [
    AuthService,
    SessionStore,
    SsoService,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
    {
      provide: APP_GUARD,
      useClass: ApiKeyGuard,
    },
  ],
  exports: [AuthService, SessionStore],
})
export class AuthModule {}
