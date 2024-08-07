import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';
import { SignUpDto } from './sign-up.dto';

export class SignUpWithTokenDto extends SignUpDto {
    @ApiProperty({
        example: 'dsfd45-4765dkhv-54876nvdsv-8475dlf',
        description: 'Токен для подтверждения регистрации',
    })
    @IsNotEmpty()
    @IsString()
    token: string;
}
