import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty } from 'class-validator';
import { SignUpMainDto } from './sign-up-main.dto';

export class SignUpDto extends SignUpMainDto {
    @ApiProperty({
        example: 1,
        description: 'Организация, к которой принадлежит пользователь',
    })
    @IsNotEmpty()
    organizationId: number;
}
