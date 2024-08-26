import {
    Body,
    Controller,
    HttpCode,
    HttpStatus,
    Post,
    Req,
    Res,
    UnauthorizedException,
    UseGuards,
} from '@nestjs/common';
import { EventPattern } from '@nestjs/microservices';
import {
    ApiBearerAuth,
    ApiConflictResponse,
    ApiCreatedResponse,
    ApiOperation,
    ApiTags,
} from '@nestjs/swagger';
import { Request, Response } from 'express';
import jwtConfig from '../config/jwt.config';
import { ActiveUser } from '../decorators/active-user.decorator';
import { ActiveUserData } from '../interfaces/active-user-data.interface';
import { AuthenticationService } from './authentication.service';
import { Auth } from './decorators/auth.decorators';
import { ChangePasswordDto } from './dto/edit/change-password.dto';
import { SignInDto } from './dto/sign-in.dto';
import { SignInWithoutPasswordDto } from './dto/sign-in/sign-in-without-password.dto';
import { SignUpWithOrganizationDto } from './dto/sign-up-with-organization.dto';
import { SignUpWithTokenDto } from './dto/sign-up-with-token.dto';
import { AuthType } from './enums/auth-type.enum';
import { AccessTokenGuardAndRole } from './guards/access-token/access-token-and-role.guard';
import { AccessTokenGuard } from './guards/access-token/access-token.guard';
import { TokensResponse } from './responses/tokens.response';

@ApiTags('Authentication')
@Auth(AuthType.None)
@Controller('authentication')
export class AuthenticationController {
    constructor(
        private readonly authenticationService: AuthenticationService,
    ) {}

    @ApiOperation({
        summary: 'Регистрация пользователя',
        description: 'Добавить описание когда будет готова дальнейшая логика',
    })
    @ApiCreatedResponse({
        status: HttpStatus.CREATED,
        description: 'Информация о том что пользователь зарегистрирован',
        type: String,
    })
    @ApiConflictResponse({
        description: 'Информация о том что пользователь уже существует',
    })
    @Post('sign-up')
    signUp(@Body() signUpDto: SignUpWithTokenDto) {
        return this.authenticationService.signUp(signUpDto);
    }

    @ApiOperation({
        summary: 'Регистрация организации',
        description: 'Добавить описание когда будет готова дальнейшая логика',
    })
    @ApiCreatedResponse({
        status: HttpStatus.CREATED,
        description: 'Информация о том что организация зарегистрирована',
        type: String,
    })
    @ApiConflictResponse({
        description: 'Информация о том что организация уже существует',
    })
    @Post('sign-up/organization')
    signUpOrganization(@Body() signUpDto: SignUpWithOrganizationDto) {
        return this.authenticationService.signUpWithOrganization(signUpDto);
    }

    @ApiOperation({
        summary: 'Вход',
        description: 'Добавить описание когда будет готова дальнейшая логика',
    })
    @ApiCreatedResponse({
        status: HttpStatus.CREATED,
        description: 'Access и refresh токены',
        type: TokensResponse,
    })
    @HttpCode(HttpStatus.OK)
    @Post('sign-in')
    async signIn(@Res() res: Response, @Body() signInDto: SignInDto) {
        const result = await this.authenticationService.signIn(signInDto);

        res.cookie('refreshToken', result.refreshToken, {
            maxAge: +jwtConfig().refreshTtl, // 30 days
            httpOnly: true,
            // secure: true, // TODO: Потребуется ли включение в production ?
        });
        return res.json({ data: result });
    }

    @ApiOperation({
        summary: 'Выход',
        description: 'Удаляет refresh токен и завершает сессию пользователя.',
    })
    @ApiBearerAuth()
    @UseGuards(AccessTokenGuard)
    @Post('sign-out')
    async logout(@ActiveUser() user: ActiveUserData, @Res() res: Response) {
        await this.authenticationService.logout(user.sub);
        // // Удаляем refresh токен из cookies
        res.clearCookie('refreshToken', {
            httpOnly: true,
            // secure: true, // Можно раскомментировать для production
        });

        return res.json({ message: 'Successfully logged out', code: 200 });
    }

    @ApiOperation({
        summary: 'Вход без пароля',
    })
    @ApiCreatedResponse({
        status: HttpStatus.CREATED,
        description: 'Access и refresh токены',
        type: TokensResponse,
    })
    @HttpCode(HttpStatus.OK)
    @Post('sign-in-without-password')
    async signInWithoutPassword(
        @Res() res: Response,
        @Body() signInDto: SignInWithoutPasswordDto,
    ) {
        const result =
            await this.authenticationService.signInWithoutPassword(signInDto);

        res.cookie('refreshToken', result.refreshToken, {
            maxAge: +jwtConfig().refreshTtl, // 30 days
            httpOnly: true,
            // secure: true, // TODO: Потребуется ли включение в production ?
        });
        return res.json({ data: result });
    }

    @ApiOperation({
        summary: 'Рефреш токенов',
        description: 'Добавить описание когда будет готова дальнейшая логика',
    })
    @ApiCreatedResponse({
        status: HttpStatus.CREATED,
        description: 'Access и refresh токены',
        type: TokensResponse,
    })
    @HttpCode(HttpStatus.OK)
    @Post('refresh-tokens')
    @ApiBearerAuth()
    async refreshToken(@Req() req: Request, @Res() res: Response) {
        const rt = req.cookies['refreshToken'];

        const result = await this.authenticationService.refreshTokens({
            refreshToken: rt,
        });

        if (!result) {
            throw new UnauthorizedException('Not authorized');
        } else {
            res.cookie('refreshToken', result.refreshToken, {
                maxAge: +jwtConfig().refreshTtl, // 30 days
                httpOnly: true,
                // secure: true, // TODO: Потребуется ли включение в production ?
            });

            return res.json({ data: { accessToken: result.accessToken } });
        }
    }

    @Post('change-password')
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Изменение пароля',
    })
    @UseGuards(AccessTokenGuardAndRole)
    // @Roles(RoleName.ADMIN)
    // @UseGuards(RolesGuard)
    changePassword(
        @Body() changePasswordDto: ChangePasswordDto,
        @ActiveUser() user: ActiveUserData,
    ) {
        return this.authenticationService.changePassword(
            user.organizationId,
            changePasswordDto,
        );
    }

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
