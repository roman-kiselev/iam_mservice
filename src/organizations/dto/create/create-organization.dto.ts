import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class CreateOrganizationDto {
    @ApiProperty({
        example: 'ООО Компания',
        description: 'Название организации',
    })
    @IsNotEmpty()
    @IsString()
    name: string;

    @ApiProperty({ example: 'г. Пенза', description: 'Название организации' })
    @IsNotEmpty()
    @IsString()
    address: string;
}
