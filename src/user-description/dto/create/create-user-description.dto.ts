import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';

export class CreateUserDescriptionDto {
    @ApiProperty({ example: 'Иван', description: 'Имя' })
    @IsOptional()
    @IsString()
    firstname: string;

    @ApiProperty({ example: 'Иванов', description: 'Фамилия' })
    @IsOptional()
    @IsString()
    lastname: string;
}
