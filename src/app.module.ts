import { MailerModule } from '@nestjs-modules/mailer';
import { MiddlewareConsumer, Module, ValidationPipe } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_FILTER, APP_PIPE } from '@nestjs/core';
import { seconds, ThrottlerModule } from '@nestjs/throttler';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Redis } from 'ioredis';
import * as Joi from 'joi';
import { ThrottlerStorageRedisService } from 'nestjs-throttler-storage-redis';
import { HttpExceptionFilter } from './exception-filters/http.exception-filter';
import { ValidationExceptionFilter } from './exception-filters/validation-exception.filter';
import { IamModule } from './iam/iam.module';
import { InviteTokensModule } from './invite-tokens/invite-tokens.module';
import { MailModule } from './mail/mail.module';
import { LoggerMiddleware } from './middlewares/logger.middleware';
import { OrganizationsModule } from './organizations/organizations.module';
import { RolesModule } from './roles/roles.module';
import { UserDescriptionModule } from './user-description/user-description.module';
import { UsersModule } from './users/users.module';
import { RedisModule } from './redis/redis.module';

type DBName = 'postgres';

@Module({
    providers: [
        {
            provide: APP_PIPE,
            useClass: ValidationPipe,
        },
        {
            provide: APP_FILTER,
            useClass: ValidationExceptionFilter,
        },
        {
            provide: APP_FILTER,
            useClass: HttpExceptionFilter,
        },
        // {
        //     provide: APP_GUARD,
        //     useClass: ThrottlerBehindProxyGuard,
        // },
    ],
    imports: [
        ConfigModule.forRoot({
            validationSchema: Joi.object({
                JWT_SECRET: Joi.string().required(),
                JWT_ACCESS_TTL: Joi.string().required(),
                JWT_REFRESH_TTL: Joi.string().required(),
                JWT_ISSUER: Joi.string().required(),
                JWT_AUDIENCE: Joi.string().required(),

                DB_TYPE: Joi.string().valid('postgres', 'mysql'),
                DB_HOST: Joi.string().required(),
                DB_PORT: Joi.number().integer().required(),
                DB_USERNAME: Joi.string().required(),
                DB_PASSWORD: Joi.string().required(),
                DB_NAME: Joi.string().required(),

                REDIS_HOST: Joi.string().required(),
                REDIS_PORT: Joi.number().integer().required(),

                THROTTLE_TTL_SECONDS: Joi.number().integer().required(),
                THROTTLE_LIMIT: Joi.number().integer().required(),

                MAIL_HOST: Joi.string().required(),
                MAIL_PORT: Joi.number().integer().required(),
                MAIL_USERNAME: Joi.string().required(),
                MAIL_PASSWORD: Joi.string().required(),
                MAIL_FROM: Joi.string().required(),
            }),
            isGlobal: true,
        }),
        TypeOrmModule.forRoot({
            type: process.env.DB_TYPE as DBName,
            host: process.env.DB_HOST,
            port: Number(process.env.DB_PORT),
            username: process.env.DB_USERNAME,
            password: process.env.DB_PASSWORD,
            database: process.env.DB_NAME,
            entities: [],
            autoLoadEntities: true,
            synchronize: true,
        }),
        ThrottlerModule.forRoot({
            throttlers: [
                {
                    ttl: seconds(Number(process.env.THROTTLE_TTL_SECONDS)),
                    limit: Number(process.env.THROTTLE_LIMIT),
                },
            ],

            storage: new ThrottlerStorageRedisService(
                new Redis({
                    host: process.env.REDIS_HOST,
                    port: Number(process.env.REDIS_PORT),
                }),
            ),
        }),
        MailerModule.forRoot({
            transport: {
                host: process.env.MAIL_HOST,
                //port: Number(process.env.MAIL_PORT),
                secure: true,
                auth: {
                    user: process.env.MAIL_USERNAME,
                    pass: process.env.MAIL_PASSWORD,
                },
            },
        }),
        IamModule,
        UserDescriptionModule,
        RolesModule,
        OrganizationsModule,
        UsersModule,
        MailModule,
        InviteTokensModule,
        RedisModule,
    ],
    controllers: [],
})
export class AppModule {
    configure(consumer: MiddlewareConsumer) {
        consumer.apply(LoggerMiddleware).forRoutes('*');
    }
}
