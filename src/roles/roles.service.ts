import {
    ConflictException,
    Injectable,
    NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateRoleDto } from './dto/create-role.dto';
import { UpdateRoleDto } from './dto/update-role.dto';
import { Role } from './entities/role.entity';

@Injectable()
export class RolesService {
    constructor(
        @InjectRepository(Role)
        private readonly roleRepository: Repository<Role>,
    ) {}

    async findOneBy(criteria: Partial<Role>) {
        const role = await this.roleRepository.findOne({ where: criteria });
        if (!role) {
            throw new NotFoundException(`Role not found`);
        }
        return role;
    }

    async createRole(dto: CreateRoleDto) {
        const roleName = await this.roleRepository.findOneBy({
            name: dto.name,
        });
        if (roleName) {
            throw new ConflictException(`Role ${dto.name} already exists`);
        }
        const role = new Role();
        role.name = dto.name;
        role.description = dto.description;
        return this.roleRepository.save(role);
    }

    async updateRole(id: number, dto: UpdateRoleDto) {
        const isRole = await this.findOneBy({ id });
        const roleUpdate = {
            ...isRole,
            ...dto,
        };

        return this.roleRepository.save(roleUpdate);
    }

    async deleteRole(id: number) {
        const role = await this.findOneBy({ id });
        return this.roleRepository.remove(role);
    }

    async findAll() {
        return this.roleRepository.find();
    }
}
