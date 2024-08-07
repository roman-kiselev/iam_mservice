import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';
import { RoleName } from '../enums/RoleName';

export class CreateRoleDto {
    @ApiProperty({
        example: RoleName.USER,
        title: 'Название роли',
        enum: RoleName,
    })
    @IsNotEmpty()
    @IsString()
    name: string;

    @ApiProperty({ example: 'Пользователь', title: 'Описание роли' })
    @IsNotEmpty()
    @IsString()
    description: string;
}
