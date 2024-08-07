import {
    Injectable,
    Logger,
    OnApplicationBootstrap,
    OnApplicationShutdown,
} from '@nestjs/common';
import { Redis } from 'ioredis';
import { InvalidatedRefreshTokenError } from '../../errors/invalidated-refresh-token.error';

@Injectable()
export class RefreshTokenIdsStorage
    implements OnApplicationBootstrap, OnApplicationShutdown
{
    private redisClient: Redis;
    private readonly logger = new Logger(RefreshTokenIdsStorage.name);

    onApplicationShutdown() {
        return this.redisClient.quit();
    }

    onApplicationBootstrap() {
        this.redisClient = new Redis({
            host: process.env.REDIS_HOST,
            port: Number(process.env.REDIS_PORT),
        });
    }

    private getKey(userId: number): string {
        return `user-${userId}`;
    }

    async insert(userId: number, tokenId: string): Promise<void> {
        await this.redisClient.set(this.getKey(userId), tokenId);
    }

    async validate(userId: number, tokenId: string): Promise<boolean> {
        const storeId = await this.redisClient.get(this.getKey(userId));
        if (storeId !== tokenId) {
            throw new InvalidatedRefreshTokenError();
        }

        return storeId === tokenId;
    }

    async invalidate(userId: number): Promise<number> {
        this.logger.debug(`Refresh token cleared for user with ID ${userId}`);
        const x = await this.redisClient.del(this.getKey(userId));

        return x;
    }
}
