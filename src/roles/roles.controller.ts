import {
    Body,
    ConflictException,
    Controller,
    Get,
    HttpStatus,
    NotFoundException,
    Param,
    Post,
} from '@nestjs/common';
import {
    ApiBearerAuth,
    ApiOperation,
    ApiResponse,
    ApiTags,
} from '@nestjs/swagger';
import { Roles } from 'src/iam/authorization/decorators/roles.decorator';

import { CreateRoleDto } from './dto/create-role.dto';
import { Role } from './entities/role.entity';
import { RoleName } from './enums/RoleName';
import { RolesService } from './roles.service';

@ApiTags('Roles')
@ApiBearerAuth()
@Roles(RoleName.ADMIN)
//@UseGuards(RolesGuard)
@Controller('roles')
export class RolesController {
    constructor(private readonly rolesService: RolesService) {}

    @ApiOperation({ summary: 'Получение всех ролей' })
    @ApiResponse({ status: HttpStatus.OK, type: [Role] })
    @Get('list')
    async findAll() {
        return this.rolesService.findAll();
    }

    @ApiOperation({ summary: 'Создание роли' })
    @ApiResponse({ status: HttpStatus.CREATED, type: Role })
    @ApiResponse({ status: HttpStatus.CONFLICT, type: ConflictException })
    @Post('create')
    async create(@Body() roleDto: CreateRoleDto) {
        return this.rolesService.createRole(roleDto);
    }

    @ApiOperation({ summary: 'Обновление роли' })
    @ApiResponse({ status: HttpStatus.OK, type: Role })
    @ApiResponse({ status: HttpStatus.NOT_FOUND, type: NotFoundException })
    @Post('update/:idRole')
    async update(
        @Body() roleDto: CreateRoleDto,
        @Param('idRole') idRole: number,
    ) {
        return this.rolesService.updateRole(idRole, roleDto);
    }

    @ApiOperation({ summary: 'Удаление роли' })
    @ApiResponse({ status: HttpStatus.OK })
    @ApiResponse({ status: HttpStatus.NOT_FOUND, type: NotFoundException })
    @Post('delete/:idRole')
    async delete(@Param('idRole') idRole: number) {
        return this.rolesService.deleteRole(idRole);
    }
}
