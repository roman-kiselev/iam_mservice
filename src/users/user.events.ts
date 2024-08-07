import { UsersService } from './users.service';

export class UsersEvents {
    constructor(private readonly usersService: UsersService) {}
}
