import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { JwtModule } from '@nestjs/jwt';
import { InviteTokensModule } from 'src/invite-tokens/invite-tokens.module';
import { OrganizationsModule } from 'src/organizations/organizations.module';
import { RedisModule } from 'src/redis/redis.module';
import { UsersModule } from 'src/users/users.module';
import { AuthenticationController } from './authentication/authentication.controller';
import { AuthenticationService } from './authentication/authentication.service';
import { AccessTokenGuard } from './authentication/guards/access-token/access-token.guard';
import { AuthenticationGuard } from './authentication/guards/authentication/authentication.guard';
import { RefreshTokenIdsStorage } from './authentication/guards/refresh-token/refresh-token-ids.storage';
import { RolesGuard } from './authorization/guards/roles/roles.guard';
import jwtConfig from './config/jwt.config';
import { BcryptService } from './hashing/bcrypt.service';
import { HashingService } from './hashing/hashing.service';

@Module({
    controllers: [AuthenticationController],
    providers: [
        {
            provide: HashingService,
            useClass: BcryptService,
        },
        {
            provide: APP_GUARD,
            useClass: AuthenticationGuard,
        },
        {
            provide: APP_GUARD,
            useClass: RolesGuard,
        },
        AccessTokenGuard,
        RefreshTokenIdsStorage,
        AuthenticationService,
    ],
    imports: [
        JwtModule.registerAsync(jwtConfig.asProvider()),
        ConfigModule.forFeature(jwtConfig),
        UsersModule,
        OrganizationsModule,
        InviteTokensModule,
        RedisModule,
        // forwardRef(() =>
        //     ClientsModule.register([
        //         {
        //             name: 'IAM_SERVICE',
        //             transport: Transport.RMQ,
        //             options: {
        //                 urls: ['amqp://localhost:5672'],
        //                 queue: 'scopework_queue',
        //                 queueOptions: {
        //                     durable: true,
        //                 },
        //             },
        //         },
        //         {
        //             name: 'IAM_SERVICE',
        //             transport: Transport.RMQ,
        //             options: {
        //                 urls: ['amqp://localhost:5672'],
        //                 queue: 'manager_queue',
        //                 queueOptions: {
        //                     durable: true,
        //                 },
        //             },
        //         },
        //     ]),
        // ),
    ],

    exports: [AuthenticationService, HashingService],
})
export class IamModule {}
