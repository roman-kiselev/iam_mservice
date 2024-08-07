import { User } from '../entities/user.entity';

export class GetUserDto {
    criteria: Partial<User>;
    relations: string[] | [];
}
