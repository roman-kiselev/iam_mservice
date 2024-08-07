import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { REQUEST_USER_KEY } from 'src/iam/iam.constants';
import { ActiveUserData } from 'src/iam/interfaces/active-user-data.interface';
import { RoleName } from 'src/roles/enums/RoleName';
import { ROLES_KEY } from '../../decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
    constructor(private readonly reflector: Reflector) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const contextRoles = this.reflector.getAllAndOverride<RoleName[]>(
            ROLES_KEY,
            [context.getHandler(), context.getClass()],
        );

        if (!contextRoles) return true;

        const user: ActiveUserData = context.switchToHttp().getRequest()[
            REQUEST_USER_KEY
        ];

        return contextRoles.some((role) => {
            return user.roles.some((userRole) => userRole === role);
        });
    }
}
