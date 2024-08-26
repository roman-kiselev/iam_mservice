import {
    CanActivate,
    ExecutionContext,
    Inject,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import jwtConfig from 'src/iam/config/jwt.config';
import { REQUEST_USER_KEY } from 'src/iam/iam.constants';

@Injectable()
export class AccessTokenGuardAndRole implements CanActivate {
    constructor(
        private readonly jwtService: JwtService,
        @Inject(jwtConfig.KEY)
        private readonly jwtConfiguration: ConfigType<typeof jwtConfig>,
    ) {}

    private extractTokenFromHeader(request: Request): string | undefined {
        const [, token] = request.headers.authorization?.split(' ') ?? [];
        return token;
    }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const token = this.extractTokenFromHeader(request);
        if (!token) {
            throw new UnauthorizedException();
        }

        try {
            const payload = this.jwtService.verify(
                token,
                this.jwtConfiguration,
            );

            request[REQUEST_USER_KEY] = payload;
        } catch (err) {
            throw new UnauthorizedException();
        }

        const isAdmin = request[REQUEST_USER_KEY].roles.some(
            (userRole) => userRole === 'admin',
        );

        if (!isAdmin) {
            return false;
        } else {
            return true;
        }
    }
}
