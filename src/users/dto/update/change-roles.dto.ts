import { ApiProperty } from '@nestjs/swagger';
import { IsArray, IsNotEmpty, IsNumber, IsPositive } from 'class-validator';

export class ChangeRolesDto {
    @ApiProperty({ type: [Number], example: [1], description: 'ID ролей' })
    @IsArray()
    @IsNotEmpty({ message: 'Roles cannot be empty' })
    @IsNumber({}, { each: true, message: 'All roles must be numbers' })
    @IsPositive({ each: true, message: 'All roles must be positive numbers' })
    roles: number[];
}
