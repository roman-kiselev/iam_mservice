import { Module } from '@nestjs/common';
import { InviteTokensModule } from 'src/invite-tokens/invite-tokens.module';
import { RedisModule } from 'src/redis/redis.module';
import { MailController } from './mail.controller';
import { MailService } from './mail.service';

@Module({
    controllers: [MailController],
    providers: [MailService],
    imports: [InviteTokensModule, RedisModule],
    exports: [MailService],
})
export class MailModule {}
