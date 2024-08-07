import { PartialType } from '@nestjs/swagger';
import { InviteToken } from 'src/invite-tokens/entities/invite-token.entity';

export class InviteTokenDto extends PartialType(InviteToken) {}
