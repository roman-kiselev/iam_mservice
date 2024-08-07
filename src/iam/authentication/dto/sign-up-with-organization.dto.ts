import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';
import { SignUpMainDto } from './sign-up-main.dto';

export class SignUpWithOrganizationDto extends SignUpMainDto {
    @ApiProperty({
        example: 'ООО Компания',
        description: 'Название организации',
    })
    @IsNotEmpty()
    @IsString()
    nameOrganization: string;

    @ApiProperty({ example: 'Адрес', description: 'Адрес' })
    @IsNotEmpty()
    @IsString()
    addressOrganization: string;

    @ApiProperty({ example: '123456', description: 'Код' })
    @IsNotEmpty()
    @IsString()
    code: string;
}
