import { IsArray, IsNotEmpty, IsOptional } from 'class-validator';

export class GetAllUsersWithDto {
    @IsNotEmpty()
    organizationId: number;
    @IsOptional()
    @IsArray()
    relations: string[];
}
