import { ApiProperty, OmitType } from '@nestjs/swagger';
import { IsNotEmpty, IsString, Length } from 'class-validator';
import { SignInDto } from '../sign-in.dto';

export class SignInWithoutPasswordDto extends OmitType(SignInDto, [
    'password',
]) {
    @ApiProperty({ example: '123456', description: 'Code OTP' })
    @IsNotEmpty()
    @IsString()
    @Length(6, 6)
    code: string;
}
