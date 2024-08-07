import { ApiProperty } from '@nestjs/swagger';
import { User } from 'src/users/entities/user.entity';
import { Column, Entity, ManyToMany, PrimaryGeneratedColumn } from 'typeorm';
import { RoleName } from '../enums/RoleName';

@Entity()
export class Role {
    @ApiProperty({ example: 1, description: 'Уникальный идентификатор' })
    @PrimaryGeneratedColumn()
    id: number;

    @ApiProperty({
        example: RoleName.USER,
        description: 'Название роли',
        enum: RoleName,
    })
    @Column({ enum: RoleName })
    name: string;

    @ApiProperty({
        example: 'Пользователь',
        description: 'Описание роли',
    })
    @Column()
    description: string;

    @ManyToMany(() => User, (user) => user.roles)
    users: User[];
}
