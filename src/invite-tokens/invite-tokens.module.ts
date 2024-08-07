import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { InviteToken } from './entities/invite-token.entity';
import { InviteTokensController } from './invite-tokens.controller';
import { InviteTokensService } from './invite-tokens.service';

@Module({
    controllers: [InviteTokensController],
    providers: [InviteTokensService],
    imports: [TypeOrmModule.forFeature([InviteToken])],
    exports: [InviteTokensService, TypeOrmModule.forFeature([InviteToken])],
})
export class InviteTokensModule {}
