import { OmitType } from '@nestjs/swagger';
import { UserDto } from './user.dto';

export class UserWithDescriptionDto extends OmitType(UserDto, [
    'roles',
    'organization',
]) {}
