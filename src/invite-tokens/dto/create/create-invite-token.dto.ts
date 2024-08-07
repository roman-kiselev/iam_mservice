import { OmitType } from '@nestjs/swagger';
import { InviteTokenDto } from '../response/invite-token.dto';

export class CreateInviteTokenDto extends OmitType(InviteTokenDto, [
    'created_at',
    'expires_at',
    'is_used',
    'id',
    'is_used',
    'token',
    'org_id',
]) {}
