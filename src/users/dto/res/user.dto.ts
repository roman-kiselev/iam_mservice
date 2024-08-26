import { OmitType } from '@nestjs/swagger';
import { User } from 'src/users/entities/user.entity';

export class UserDto extends OmitType(User, ['password']) {}
