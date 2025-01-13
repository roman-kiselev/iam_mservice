import {
    ConflictException,
    ForbiddenException,
    Injectable,
    NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { SignUpDto } from 'src/iam/authentication/dto/sign-up.dto';
import { OrganizationsService } from 'src/organizations/organizations.service';
import { RoleName } from 'src/roles/enums/RoleName';
import { RolesService } from 'src/roles/roles.service';
import { UserDescriptionService } from 'src/user-description/user-description.service';
import { Repository } from 'typeorm';
import { ChangeRolesDto } from './dto/update/change-roles.dto';
import { User } from './entities/user.entity';

@Injectable()
export class UsersService {
    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
        private organizationService: OrganizationsService,
        private rolesService: RolesService,
        private readonly userDescriptionService: UserDescriptionService,
    ) {}

    private async addRoles(user: User, roles: number[]) {
        // const user = await this.userRepository.findOneBy({ id: userId });
        const rolesPromise = roles.map((roleId) => {
            return this.rolesService.findOneBy({ id: roleId });
        });

        const rolesArr = await Promise.all(rolesPromise);
        // const fullRoles = [...user.roles, ...rolesArr];

        return this.userRepository.update(user.id, {
            roles: rolesArr,
        });
    }

    // private async removeRoles(userId: number, roles: number[]) {
    //     const user = await this.userRepository.findOneBy({ id: userId });
    //     const rolesPromise = roles.map((roleId) => {
    //         return this.rolesService.findOneBy({ id: roleId });
    //     });

    //     const rolesArr = await Promise.all(rolesPromise);
    // }

    async findOneBy(criteria: Partial<User>, relations: string[] = []) {
        const user = await this.userRepository.findOne({
            where: criteria,
            relations,
        });
        if (!user) {
            throw new NotFoundException('User not found');
        }
        return user;
    }

    async findOneWithRelation(
        criteria: Partial<User>,
        relations: string[] = [],
    ) {
        const user = await this.userRepository.findOne({
            where: criteria,
            relations,
        });
        if (!user) {
            throw new NotFoundException('User not found');
        }

        return user;
    }

    async checkUniqueEmail(email: string) {
        const user = await this.userRepository.findOneBy({ email });
        if (user) {
            return user;
        }
        return null;
    }

    async createUser(dto: SignUpDto) {
        const isUser = await this.userRepository.findOneBy({
            email: dto.email,
        });
        if (isUser) {
            throw new ConflictException('User already exists');
        }
        const role = await this.rolesService.findOneBy({
            name: dto.role ? dto.role : RoleName.USER,
        });
        const organization = await this.organizationService.findUnique(
            +dto.organizationId,
        );
        const userDecription =
            await this.userDescriptionService.createUserDescription({
                firstname: dto.firstname,
                lastname: dto.lastname,
            });

        const user = new User();
        user.email = dto.email;
        user.password = dto.password;
        user.organization = organization;
        user.roles = [role];
        user.description = userDecription;
        const userCreated = await this.userRepository.save(user);

        return userCreated;
    }

    async getAllUsers(organizationId: number) {
        const organization =
            await this.organizationService.findUnique(organizationId);

        return await this.userRepository.find({
            where: {
                organization: organization,
            },
        });
    }

    async getAllUsersWith(organizationId: number, relations: string[]) {
        if (!organizationId) {
            throw new ForbiddenException('Organization id is required');
        }
        const organization = await this.organizationService.getOrganigationBy({
            id: organizationId,
        });

        const users = (
            await this.userRepository.find({
                where: {
                    organization: organization,
                },
                relations: relations ?? [],
            })
        ).map((user) => {
            delete user.password;
            return user;
        });

        return users;
    }

    async updateUser(id: number, dto: Partial<SignUpDto>) {
        const user = await this.userRepository.findOneBy({ id });
        if (!user) {
            throw new NotFoundException('User not found');
        }
        const userUpdated = await this.userRepository.save({ ...user, ...dto });

        return userUpdated;
    }

    async changeRoles(id: number, dto: ChangeRolesDto) {
        const user = await this.findOneBy({ id }, ['roles', 'description']);
        const rolesPromise = dto.roles.map((role) => {
            return this.rolesService.findOneBy({ id: role });
        });
        const roles = await Promise.all(rolesPromise);
        user.roles = [];

        return this.userRepository.save({ ...user, roles });
    }
}
