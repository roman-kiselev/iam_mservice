import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, MinLength } from 'class-validator';

export class SignInDto {
    @ApiProperty({
        example: 'email@email.com',
        description: 'User email',
    })
    @IsEmail()
    email: string;

    @ApiProperty({
        example: '12345678',
        description: 'User password, min length is 8',
    })
    @MinLength(4)
    password: string;
}
