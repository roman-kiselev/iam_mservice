import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsNumber } from 'class-validator';

export class ChangePasswordDto {
    @ApiProperty({ example: 1, title: 'Идентификатор пользователя' })
    @IsNotEmpty()
    @IsNumber()
    userId: number;
}
