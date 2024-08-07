import { forwardRef, Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { OrganizationsModule } from 'src/organizations/organizations.module';
import { RolesModule } from 'src/roles/roles.module';
import { UserDescriptionModule } from 'src/user-description/user-description.module';
import { User } from './entities/user.entity';
import { UsersEvents } from './user.events';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';

@Module({
    controllers: [UsersController],
    providers: [UsersEvents, UsersService],
    imports: [
        TypeOrmModule.forFeature([User]),
        forwardRef(() => OrganizationsModule),
        RolesModule,
        UserDescriptionModule,
    ],
    exports: [TypeOrmModule.forFeature([User]), UsersService],
})
export class UsersModule {}
