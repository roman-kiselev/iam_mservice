import { EventPattern } from '@nestjs/microservices';
import { AuthenticationService } from './authentication.service';

export class AuthenticationEvents {
    constructor(
        private readonly authenticationService: AuthenticationService,
    ) {}

    @EventPattern('check-token')
    async handleCheckToken(data: string) {
        return this.authenticationService.verifyToken(data);
    }

    @EventPattern('get-roles')
    async handleGetRoles(data: string) {
        return this.authenticationService.getRoles(data);
    }

    @EventPattern('get-user')
    async handleGetUser(data: string) {
        return this.authenticationService.getUser(data);
    }
}
