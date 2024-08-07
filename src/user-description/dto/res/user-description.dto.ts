import { PartialType } from '@nestjs/swagger';
import { UserDecription } from 'src/user-description/entities/user-description.entity';

export class UserDescriptionDto extends PartialType(UserDecription) {}
