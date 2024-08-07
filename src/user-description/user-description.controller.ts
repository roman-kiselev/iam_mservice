import {
    Body,
    Controller,
    Get,
    HttpStatus,
    Param,
    Patch,
    Post,
} from '@nestjs/common';
import {
    ApiBearerAuth,
    ApiOperation,
    ApiResponse,
    ApiTags,
} from '@nestjs/swagger';
import { CreateUserDescriptionDto } from './dto/create/create-user-description.dto';
import { UserDescriptionDto } from './dto/res/user-description.dto';
import { UserDescriptionService } from './user-description.service';

@ApiBearerAuth()
@ApiTags('User Description')
@Controller('user-description')
export class UserDescriptionController {
    constructor(
        private readonly userDescriptionService: UserDescriptionService,
    ) {}

    @ApiOperation({
        summary: 'Получить описание пользователя',
    })
    @ApiResponse({
        status: HttpStatus.OK,
        description: 'Описание пользователя',
        type: UserDescriptionDto,
    })
    @Get('/:id')
    async getUserDescription(@Param('id') id: number) {
        return this.userDescriptionService.getUserDescription(id);
    }

    @ApiOperation({
        summary: 'Создать описание пользователя',
    })
    @ApiResponse({
        status: HttpStatus.CREATED,
        description: 'Описание пользователя',
        type: UserDescriptionDto,
    })
    @Post('/create')
    async createUserDescription(@Body() dto: CreateUserDescriptionDto) {
        return this.userDescriptionService.createUserDescription(dto);
    }

    @ApiOperation({
        summary: 'Обновить описание пользователя',
    })
    @ApiResponse({
        status: HttpStatus.OK,
        description: 'Описание пользователя',
        type: UserDescriptionDto,
    })
    @Patch('/update/:id')
    async updateUserDescription(
        @Param('id') id: number,
        @Body() dto: CreateUserDescriptionDto,
    ) {
        return this.userDescriptionService.updateUserDescription(id, dto);
    }
}
