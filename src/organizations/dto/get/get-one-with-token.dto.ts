import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class GetOneWithTokenDto {
    @ApiProperty({
        example: 'asdad-mldkfg-nds-shgfdjshf',
        description: 'Токен',
    })
    @IsNotEmpty()
    @IsString()
    token: string;
}
