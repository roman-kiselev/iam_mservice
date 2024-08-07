import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty } from 'class-validator';

export class EmailDto {
    @ApiProperty({
        example: 'stroi.energoservis@yandex.ru',
        description: 'Почтовый адрес',
    })
    @IsNotEmpty()
    @IsEmail()
    email: string;
}
