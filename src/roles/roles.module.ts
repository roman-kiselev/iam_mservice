import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Role } from './entities/role.entity';
import { RolesController } from './roles.controller';
import { RolesService } from './roles.service';

@Module({
    controllers: [RolesController],
    providers: [RolesService],
    imports: [TypeOrmModule.forFeature([Role])],
    exports: [TypeOrmModule.forFeature([Role]), RolesService],
})
export class RolesModule {}
