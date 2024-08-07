import {
    Body,
    Controller,
    Get,
    HttpStatus,
    Param,
    Patch,
    Post,
    Query,
    UseGuards,
} from '@nestjs/common';
import {
    ApiBearerAuth,
    ApiOperation,
    ApiResponse,
    ApiTags,
} from '@nestjs/swagger';
import { Auth } from 'src/iam/authentication/decorators/auth.decorators';
import { AuthType } from 'src/iam/authentication/enums/auth-type.enum';
import { Roles } from 'src/iam/authorization/decorators/roles.decorator';
import { RolesGuard } from 'src/iam/authorization/guards/roles/roles.guard';
import { ActiveUser } from 'src/iam/decorators/active-user.decorator';
import { ActiveUserData } from 'src/iam/interfaces/active-user-data.interface';
import { RoleName } from 'src/roles/enums/RoleName';
import { CreateInviteTokenDto } from './dto/create/create-invite-token.dto';
import { CheckTokenDto } from './dto/get/check-token.dto';
import { InviteTokenWithExpiredDto } from './dto/response/invite-token-with-expired.dto';
import { InviteTokenDto } from './dto/response/invite-token.dto';
import { InviteToken } from './entities/invite-token.entity';
import { InviteTokensService } from './invite-tokens.service';

@ApiTags('Invite Tokens')
@Controller('invite-tokens')
export class InviteTokensController {
    constructor(private readonly inviteTokensService: InviteTokensService) {}

    @ApiBearerAuth()
    @ApiOperation({ summary: 'Получение всех токенов для орагнизации' })
    @ApiResponse({ status: HttpStatus.OK, type: [InviteToken] })
    @Roles(RoleName.ADMIN)
    @UseGuards(RolesGuard)
    @Get('/')
    async getInviteTokens(@ActiveUser() user: ActiveUserData) {
        return await this.inviteTokensService.getAllTokens(user.organizationId);
    }

    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Получение всех токенов для орагнизации со сроком действия',
    })
    @ApiResponse({ status: HttpStatus.OK, type: [InviteTokenWithExpiredDto] })
    @Roles(RoleName.ADMIN)
    @UseGuards(RolesGuard)
    @Get('/list')
    async getInviteTokensWithExpired(@ActiveUser() user: ActiveUserData) {
        return await this.inviteTokensService.getInviteTokensWithIsExpired(
            user.organizationId,
        );
    }

    @ApiBearerAuth()
    @ApiOperation({ summary: 'Создание токена для орагнизации' })
    @ApiResponse({ status: HttpStatus.OK, type: InviteToken })
    @Roles(RoleName.ADMIN)
    @UseGuards(RolesGuard)
    @Post('/')
    async createInviteTokens(
        @Body() dto: CreateInviteTokenDto,
        @ActiveUser() user: ActiveUserData,
    ) {
        return await this.inviteTokensService.create(dto, user.organizationId);
    }

    @ApiOperation({ summary: 'Подтверждение токена' })
    @ApiResponse({ status: HttpStatus.OK, type: InviteToken })
    @Get('/invitation')
    async getInviteToken(@ActiveUser() user: ActiveUserData) {
        // return await this.inviteTokensService.getInviteToken();
    }

    @ApiBearerAuth()
    @Auth(AuthType.None)
    @ApiOperation({ summary: 'Проверка токена' })
    @ApiResponse({ status: HttpStatus.OK, type: InviteTokenDto })
    @Get('/check')
    async checkToken(@Query() queryDto: CheckTokenDto) {
        return await this.inviteTokensService.checkExpiredToken(queryDto.token);
    }

    @ApiBearerAuth()
    @Roles(RoleName.ADMIN)
    @UseGuards(RolesGuard)
    @ApiOperation({ summary: 'Обновить токен' })
    @ApiResponse({ status: HttpStatus.OK, type: InviteTokenDto })
    @Patch('update/:id')
    async updateToken(
        @Param('id') id: number,
        @ActiveUser() user: ActiveUserData,
    ) {
        return await this.inviteTokensService.updateToken(
            id,
            user.organizationId,
        );
    }
}
