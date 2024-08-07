import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateUserDescriptionDto } from './dto/create/create-user-description.dto';
import { UpdateUserDescriptionDto } from './dto/update/update-user-description.dto';
import { UserDecription } from './entities/user-description.entity';

@Injectable()
export class UserDescriptionService {
    constructor(
        @InjectRepository(UserDecription)
        private userDescriptionRepository: Repository<UserDecription>,
    ) {}

    async getUserDescription(id: number) {
        const userDescription = await this.userDescriptionRepository.findOne({
            where: { id },
        });
        if (!userDescription) {
            throw new NotFoundException('User description not found');
        }

        return userDescription;
    }

    async createUserDescription(dto: CreateUserDescriptionDto) {
        const userDescription = new UserDecription();

        userDescription.firstname = dto.firstname;
        userDescription.lastname = dto.lastname;
        return this.userDescriptionRepository.save(userDescription);
    }

    async updateUserDescription(id: number, dto: UpdateUserDescriptionDto) {
        let userDescription = await this.userDescriptionRepository.findOne({
            where: { id },
        });
        userDescription = { ...userDescription, ...dto };
        return this.userDescriptionRepository.save(userDescription);
    }
}
