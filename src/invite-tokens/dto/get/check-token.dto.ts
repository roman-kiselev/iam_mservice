import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class CheckTokenDto {
    @ApiProperty({ example: 'sadsasd-asdasd-asd-asdaf', description: 'Токен' })
    @IsNotEmpty()
    @IsString()
    token: string;
}
