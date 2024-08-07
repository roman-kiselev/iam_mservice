import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';
import { Role } from '../entities/role.entity';
import { RoleName } from '../enums/RoleName';

export class UpdateRoleDto implements Partial<Role> {
    @ApiProperty({
        example: RoleName.USER,
        title: 'Название роли',
        enum: RoleName,
    })
    @IsNotEmpty()
    @IsString()
    name?: string;

    @ApiProperty({ example: 'Пользователь', title: 'Описание роли' })
    @IsNotEmpty()
    @IsString()
    description: string;
}
