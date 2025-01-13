import {
    BadRequestException,
    ConflictException,
    ForbiddenException,
    Inject,
    Injectable,
    NotFoundException,
    UnauthorizedException,
} from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { randomUUID } from 'crypto';
import { TimeHelper } from 'src/invite-tokens/helpers/time.helper';
import { InviteTokensService } from 'src/invite-tokens/invite-tokens.service';
import { MailService } from 'src/mail/mail.service';
import { OrganizationsService } from 'src/organizations/organizations.service';
import { RedisService } from 'src/redis/redis.service';
import { RoleName } from 'src/roles/enums/RoleName';
import { User } from 'src/users/entities/user.entity';
import { UsersService } from 'src/users/users.service';
import jwtConfig from '../config/jwt.config';
import { HashingService } from '../hashing/hashing.service';
import { ActiveUserData } from '../interfaces/active-user-data.interface';
import { RefreshTokenData } from '../interfaces/refresh-token-data.interface';
import { ChangePasswordDto } from './dto/edit/change-password.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { SignInDto } from './dto/sign-in.dto';
import { SignInWithoutPasswordDto } from './dto/sign-in/sign-in-without-password.dto';
import { SignUpWithOrganizationDto } from './dto/sign-up-with-organization.dto';
import { SignUpWithTokenDto } from './dto/sign-up-with-token.dto';
import { InvalidatedRefreshTokenError } from './errors/invalidated-refresh-token.error';
import { RefreshTokenIdsStorage } from './guards/refresh-token/refresh-token-ids.storage';

@Injectable()
export class AuthenticationService {
    constructor(
        private organizationService: OrganizationsService,
        private userService: UsersService,
        private hashingService: HashingService,
        private readonly jwtService: JwtService,
        @Inject(jwtConfig.KEY)
        private readonly jwtConfiguration: ConfigType<typeof jwtConfig>,
        private readonly refreshTokenIdsStorage: RefreshTokenIdsStorage,
        private readonly inviteTokenService: InviteTokensService,
        private readonly redisService: RedisService,
        private readonly mailService: MailService,
    ) {}

    private async generateRandomPassword(
        length: number = 8,
        includeSpecialCharacters: boolean = true,
    ): Promise<string> {
        const lowerCaseChars = 'abcdefghijklmnopqrstuvwxyz';
        const upperCaseChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const numericChars = '0123456789';
        const specialChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';

        // Объединяем все символы в один набор
        let allChars = lowerCaseChars + upperCaseChars + numericChars;

        if (includeSpecialCharacters) {
            allChars += specialChars;
        }

        let password = '';

        for (let i = 0; i < length; i++) {
            const randomIndex = Math.floor(Math.random() * allChars.length);
            password += allChars[randomIndex];
        }

        return password;
    }

    private async signToken<T>(userId: number, expiresIn: string, payload?: T) {
        return await this.jwtService.signAsync(
            {
                sub: userId,
                ...payload,
            },
            {
                secret: this.jwtConfiguration.secret,
                audience: this.jwtConfiguration.audience,
                issuer: this.jwtConfiguration.issuer,
                expiresIn,
            },
        );
    }

    private async generateTokens(user: User) {
        const refreshTokenId = randomUUID();
        const [accessToken, refreshToken] = await Promise.all([
            this.signToken<Partial<ActiveUserData>>(
                user.id,
                this.jwtConfiguration.accessTtl,
                {
                    email: user.email,
                    roles: user.roles.map((role) => role.name),
                    banned: user.banned,
                    organizationId: user.organization.id,
                },
            ),
            this.signToken<Partial<RefreshTokenData>>(
                user.id,
                this.jwtConfiguration.refreshTtl,
                {
                    refreshTokenId,
                },
            ),
        ]);

        await this.refreshTokenIdsStorage.insert(user.id, refreshTokenId);
        return { accessToken, refreshToken };
    }

    async signUp(dto: SignUpWithTokenDto) {
        const user = await this.userService.checkUniqueEmail(dto.email);
        if (user) {
            throw new ConflictException(
                `User with email ${dto.email} already exists`,
            );
        }

        const inviteToken = await this.inviteTokenService.getTokenByEmail(
            dto.email,
            dto.organizationId,
        );
        const isInviteToken = dto.token === inviteToken.token;
        const isExpired = new TimeHelper().isExpired(
            new Date(inviteToken.expires_at).toISOString(),
        );
        if (!isInviteToken || isExpired) {
            throw new ForbiddenException('Invalid invite token');
        }

        const hashPassword = await this.hashingService.hash(dto.password);
        const candidate = await this.userService.createUser({
            ...dto,
            password: hashPassword,
        });

        if (!candidate) {
            throw new ConflictException('User not created');
        }

        await this.inviteTokenService.setIsUsed(
            inviteToken.id,
            dto.organizationId,
        );

        return candidate;
    }

    async signUpWithOrganization(dto: SignUpWithOrganizationDto) {
        const key = `verification_code:${dto.email}`;
        const user = await this.userService.checkUniqueEmail(dto.email);
        if (user) {
            throw new ConflictException(
                `User with email ${dto.email} already exists`,
            );
        }

        const otpToken = await this.redisService.get(key);
        if (otpToken === dto.code) {
            const organization = await this.organizationService.create({
                name: dto.nameOrganization,
                address: dto.addressOrganization,
            });

            const hashPassword = await this.hashingService.hash(dto.password);
            const candidate = await this.userService.createUser({
                email: dto.email,
                password: hashPassword,
                role: RoleName.ADMIN,
                organizationId: organization.id,
                firstname: dto.firstname,
                lastname: dto.lastname,
            });
            if (!candidate) {
                throw new ConflictException('User not created');
            }
            await this.redisService.del(key); // Удаляем OTP после использования
            return candidate;
        }

        throw new ForbiddenException('Invalid code');
    }

    async signIn(dto: SignInDto) {
        const user = await this.userService.findOneWithRelation(
            { email: dto.email },
            ['organization', 'roles'],
        );

        if (user instanceof User) {
            if (user.banned === true) {
                throw new ForbiddenException('Нет доступа');
            }

            const isEqual = await this.hashingService.compare(
                dto.password,
                user.password,
            );

            if (!isEqual) {
                throw new ForbiddenException(
                    'Пароль или почта введены неверно',
                );
            }

            const result = await this.generateTokens(user);

            return result;
        }
    }

    async logout(id: number) {
        return await this.refreshTokenIdsStorage.invalidate(id);
    }

    async signInWithoutPassword(dto: SignInWithoutPasswordDto) {
        const user = await this.userService.findOneWithRelation(
            { email: dto.email },
            ['organization', 'roles'],
        );

        if (user instanceof User) {
            if (user.banned === true) {
                throw new ForbiddenException('User is banned');
            }

            // Проверим не истёкло ли время кода
            const isExpired = await this.redisService.ttl(
                `verification_code:${dto.email}`,
            );

            if (isExpired < 0) {
                throw new ForbiddenException('Code expired');
            }
            const isEqual =
                (await this.redisService.get(
                    `verification_code:${dto.email}`,
                )) === dto.code;

            if (!isEqual) {
                throw new ForbiddenException('Code is incorrect');
            }

            const result = await this.generateTokens(user);
            return result;
        }
    }
    async refreshTokens(refreshTokenDto: RefreshTokenDto) {
        try {
            const { sub, refreshTokenId } =
                await this.jwtService.verifyAsync<RefreshTokenData>(
                    refreshTokenDto.refreshToken,
                    {
                        secret: this.jwtConfiguration.secret,
                        audience: this.jwtConfiguration.audience,
                        issuer: this.jwtConfiguration.issuer,
                    },
                );

            const user = await this.userService.findOneWithRelation(
                { id: sub },
                ['roles', 'organization'],
            );

            if (user instanceof User) {
                const isValid = await this.refreshTokenIdsStorage.validate(
                    user.id,
                    refreshTokenId,
                );

                if (isValid) {
                    await this.refreshTokenIdsStorage.invalidate(user.id);
                } else {
                    throw new ConflictException('Refresh token is invalid');
                }

                return this.generateTokens(user);
            }
        } catch (error) {
            if (error instanceof InvalidatedRefreshTokenError) {
                throw new UnauthorizedException('Access denied');
            }

            throw new UnauthorizedException();
        }
    }

    async verifyToken(token: string) {
        const result = await this.jwtService.verifyAsync(token, {
            secret: this.jwtConfiguration.secret,
            audience: this.jwtConfiguration.audience,
            issuer: this.jwtConfiguration.issuer,
        });

        if (result) {
            return token;
        }
        return null;
    }

    async getRoles(accessToken: string) {
        try {
            const result: ActiveUserData = await this.jwtService.verifyAsync(
                accessToken,
                {
                    secret: this.jwtConfiguration.secret,
                    audience: this.jwtConfiguration.audience,
                    issuer: this.jwtConfiguration.issuer,
                },
            );

            return result.roles;
        } catch (e) {
            throw new UnauthorizedException('Not authorized');
        }
    }

    async getUser(accessToken: string) {
        try {
            const result: ActiveUserData = await this.jwtService.verifyAsync(
                accessToken,
                {
                    secret: this.jwtConfiguration.secret,
                    audience: this.jwtConfiguration.audience,
                    issuer: this.jwtConfiguration.issuer,
                },
            );

            return result;
        } catch (e) {
            throw new UnauthorizedException('Not authorized');
        }
    }

    async changePassword(organizationId: number, dto: ChangePasswordDto) {
        const organization =
            await this.organizationService.findUnique(organizationId);
        if (!organization) {
            throw new NotFoundException('Organization not found');
        }
        const newPassword = await this.generateRandomPassword(8, true);
        const hashPassword = await this.hashingService.hash(newPassword);
        const user = await this.userService.findOneBy({
            id: dto.userId,
            organization,
        });
        if (!user) {
            throw new NotFoundException('User not found');
        }
        const result = await this.userService.updateUser(user.id, {
            ...user,
            password: hashPassword,
        });

        if (!result) {
            throw new BadRequestException('Error while changing password');
        }

        try {
            await this.mailService.sendNewPassword(user.email, newPassword);
            return true;
        } catch (e) {
            console.error(e);
            throw new Error('Error while sending email');
        }
    }
}
