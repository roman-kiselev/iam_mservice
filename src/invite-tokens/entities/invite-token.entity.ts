import { ApiProperty } from '@nestjs/swagger';
import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { v4 as uuid } from 'uuid';
import { TimeHelper } from '../helpers/time.helper';

@Entity()
export class InviteToken {
    @ApiProperty({ example: 1, description: 'Уникальный идентификатор' })
    @PrimaryGeneratedColumn()
    id: number;

    @ApiProperty({
        example: 1,
        description: 'Уникальный идентификатор организации',
    })
    @Column({ nullable: false })
    org_id: number;

    @ApiProperty({ example: `${uuid()}`, description: 'Токен' })
    @Column({ unique: true, nullable: false })
    token: string;

    @ApiProperty({ example: 'email@email.ru', description: 'Email' })
    @Column({ nullable: false })
    email: string;

    @ApiProperty({ example: false, description: 'Использован' })
    @Column({ default: false })
    is_used: boolean;

    @ApiProperty({
        example: new TimeHelper().getCurrentTime(),
        description: 'Дата cоздания',
    })
    @Column({ nullable: false })
    created_at: Date;

    @ApiProperty({
        example: new TimeHelper().getExpiresAt(),
        description: 'Время окончания',
    })
    @Column({ nullable: false })
    expires_at: Date;
}
