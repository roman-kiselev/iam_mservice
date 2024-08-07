import { ApiProperty, PartialType } from '@nestjs/swagger';
import { InviteTokenDto } from './invite-token.dto';

export class InviteTokenWithExpiredDto extends PartialType(InviteTokenDto) {
    @ApiProperty({ example: false, description: 'Срок действия токена истек' })
    expired: boolean;
}
