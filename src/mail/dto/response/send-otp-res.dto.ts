import { ApiProperty } from '@nestjs/swagger';

export class SendOtpResDto {
    @ApiProperty({
        example: 'OTP код отправлен на вашу почту',
        description: 'Сообщение',
    })
    message: string;

    @ApiProperty({ example: 200, description: 'Код ответа' })
    code: number;
}
