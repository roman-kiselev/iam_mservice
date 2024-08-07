import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { InviteTokensService } from 'src/invite-tokens/invite-tokens.service';
import { Repository } from 'typeorm';
import { CreateOrganizationDto } from './dto/create/create-organization.dto';
import { Organization } from './entities/organization.entity';

@Injectable()
export class OrganizationsService {
    constructor(
        @InjectRepository(Organization)
        private readonly organizationRepository: Repository<Organization>,
        private readonly inviteTokenService: InviteTokensService,
    ) {}

    async findUnique(id: number) {
        const organization = await this.organizationRepository.findOneBy({
            id,
        });
        if (!organization) {
            throw new NotFoundException('Организация не найдена');
        }
        return organization;
    }

    async getOrganigationBy(criteria: Partial<Organization>) {
        const organization = await this.organizationRepository.findOne({
            where: criteria,
        });
        if (!organization) {
            throw new NotFoundException(`Organization not found`);
        }

        return organization;
    }

    async create(dto: CreateOrganizationDto) {
        const organization = new Organization();
        organization.name = dto.name;
        organization.address = dto.address;
        return this.organizationRepository.save(organization);
    }

    delete(id: number) {
        return this.organizationRepository.delete(id);
    }

    async getOrganizationByIdWithToken(token: string, id: number) {
        const inviteToken =
            await this.inviteTokenService.isTokenWithOrganization(token, id);
        if (!token) {
            throw new NotFoundException('Invite token not found');
        }
        const organization = await this.findUnique(inviteToken.org_id);

        return organization;
    }
}
