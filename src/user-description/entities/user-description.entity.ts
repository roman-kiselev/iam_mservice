import { ApiProperty } from '@nestjs/swagger';
import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class UserDecription {
    @ApiProperty({ example: 1, description: 'Уникальный идентификатор' })
    @PrimaryGeneratedColumn()
    id: number;

    @ApiProperty({ example: 'Иван', description: 'Имя' })
    @Column()
    firstname: string;

    @ApiProperty({ example: 'Иванов', description: 'Фамилия' })
    @Column()
    lastname: string;

    @ApiProperty({ example: null, description: 'Время удаления' })
    @Column({ nullable: true })
    deletedAt: Date;
}
