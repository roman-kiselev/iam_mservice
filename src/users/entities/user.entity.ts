import { ApiProperty } from '@nestjs/swagger';
import { Organization } from 'src/organizations/entities/organization.entity';
import { Role } from 'src/roles/entities/role.entity';
import { UserDecription } from 'src/user-description/entities/user-description.entity';
import {
    Column,
    Entity,
    JoinColumn,
    JoinTable,
    ManyToMany,
    ManyToOne,
    OneToOne,
    PrimaryGeneratedColumn,
} from 'typeorm';

@Entity()
export class User {
    @ApiProperty({ example: 1, description: 'Уникальный идентификатор' })
    @PrimaryGeneratedColumn()
    id: number;

    @ApiProperty({ example: 'email@email.ru', description: 'Email' })
    @Column({ unique: true })
    email: string;

    @ApiProperty({ example: 'admin', description: 'Пароль' })
    @Column()
    password: string;

    @ApiProperty({ example: 'true', description: 'Ban' })
    @Column({ default: false })
    banned: boolean;

    @ApiProperty({ example: '12.12.2022', description: 'Дата' })
    @Column({ nullable: true })
    deletedAt: Date;

    @ManyToOne(() => Organization, (organization) => organization.users)
    organization: Organization;

    @ManyToMany(() => Role, (role) => role.users)
    @JoinTable()
    roles: Role[];

    @OneToOne(() => UserDecription)
    @JoinColumn()
    description: UserDecription;
}
