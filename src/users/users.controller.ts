import { Controller, Get, Param } from '@nestjs/common';
import { EventPattern } from '@nestjs/microservices';
import { Auth } from 'src/iam/authentication/decorators/auth.decorators';
import { AuthType } from 'src/iam/authentication/enums/auth-type.enum';
import { GetAllUsersWithDto } from './dtoEvents/get-all-users-with.dto';
import { GetUserDto } from './dtoEvents/get-user-by.dto';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
    constructor(private readonly usersService: UsersService) {}

    @Auth(AuthType.None)
    @Get('/:id')
    async getUser(@Param('id') id: number) {
        return this.usersService.findOneBy({ id }, ['description']);
    }

    @EventPattern('get-all-users')
    async getAllUsers(organizationId: number) {
        return this.usersService.getAllUsers(organizationId);
    }

    @EventPattern('get-all-users-with')
    async getAllUsersWith(dto: GetAllUsersWithDto) {
        return this.usersService.getAllUsersWith(
            dto.organizationId,
            dto.relations,
        );
    }

    @EventPattern('get-user-by')
    async getUserBy(dto: GetUserDto) {
        return this.usersService.findOneWithRelation(
            dto.criteria,
            dto.relations,
        );
    }
}
