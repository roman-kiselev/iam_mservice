import { Body, Controller, Get, Param, Patch } from '@nestjs/common';
import { EventPattern } from '@nestjs/microservices';
import {
    ApiBearerAuth,
    ApiOkResponse,
    ApiOperation,
    ApiTags,
} from '@nestjs/swagger';
import { Auth } from 'src/iam/authentication/decorators/auth.decorators';
import { AuthType } from 'src/iam/authentication/enums/auth-type.enum';
import { ActiveUser } from 'src/iam/decorators/active-user.decorator';
import { ActiveUserData } from 'src/iam/interfaces/active-user-data.interface';
import { UserWithDescriptionDto } from './dto/res/user-with-description.dto';
import { ChangeRolesDto } from './dto/update/change-roles.dto';
import { GetAllUsersWithDto } from './dtoEvents/get-all-users-with.dto';
import { GetUserDto } from './dtoEvents/get-user-by.dto';
import { UsersService } from './users.service';

@ApiTags('Users')
@ApiBearerAuth()
@Auth(AuthType.Bearer)
@Controller('users')
export class UsersController {
    constructor(private readonly usersService: UsersService) {}

    @Get('list')
    @ApiOperation({ summary: 'Получить всех пользователей' })
    @ApiOkResponse({ type: [UserWithDescriptionDto] })
    async getAllUsers(@ActiveUser() user: ActiveUserData) {
        console.log(user);
        return this.usersService.getAllUsersWith(user.organizationId, [
            'description',
        ]);
    }

    @Get('/one/:id')
    @ApiOperation({ summary: 'Получить пользователя' })
    @ApiOkResponse({ type: UserWithDescriptionDto })
    async getOneUser(@Param('id') id: number) {
        return this.usersService.findOneBy({ id }, ['description', 'roles']);
    }

    @Auth(AuthType.None)
    @Patch('/change-roles/:id')
    // @Roles(RoleName.ADMIN)
    // @UseGuards(RolesGuard)
    @ApiOperation({ summary: 'Изменить роли' })
    async changeRoles(@Param('id') id: number, @Body() dto: ChangeRolesDto) {
        return this.usersService.changeRoles(id, dto);
    }

    @Auth(AuthType.None)
    @Get('/:id')
    async getUser(@Param('id') id: number) {
        return this.usersService.findOneBy({ id }, ['description']);
    }

    @EventPattern('get-all-users')
    async getAllUsersEvent(organizationId: number) {
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
