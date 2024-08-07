import { ApiProperty } from '@nestjs/swagger';
import { User } from 'src/users/entities/user.entity';
import { Column, Entity, OneToMany, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class Organization {
    @ApiProperty({ example: 1, description: 'Уникальный идентификатор' })
    @PrimaryGeneratedColumn()
    id: number;

    @ApiProperty({
        example: 'ООО Компания',
        description: 'Название организации',
    })
    @Column()
    name: string;

    @ApiProperty({ example: 'Адрес', description: 'Адрес' })
    @Column()
    address: string;

    @OneToMany(() => User, (user) => user.organization)
    users: User[];
}
