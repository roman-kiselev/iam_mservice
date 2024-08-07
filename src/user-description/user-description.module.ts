import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserDecription } from './entities/user-description.entity';
import { UserDescriptionController } from './user-description.controller';
import { UserDescriptionService } from './user-description.service';

@Module({
    controllers: [UserDescriptionController],
    providers: [UserDescriptionService],
    imports: [TypeOrmModule.forFeature([UserDecription])],
    exports: [
        TypeOrmModule.forFeature([UserDecription]),
        UserDescriptionService,
    ],
})
export class UserDescriptionModule {}
