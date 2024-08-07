import { Controller, Get, HttpStatus, Param, Query } from '@nestjs/common';
import { ApiOperation, ApiQuery, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Auth } from 'src/iam/authentication/decorators/auth.decorators';
import { AuthType } from 'src/iam/authentication/enums/auth-type.enum';
import { GetOneWithTokenDto } from './dto/get/get-one-with-token.dto';
import { Organization } from './entities/organization.entity';
import { OrganizationsService } from './organizations.service';

@ApiTags('Оrganizations')
@Controller('organizations')
export class OrganizationsController {
    constructor(private readonly organizationsService: OrganizationsService) {}

    @ApiOperation({ summary: 'Получить одну организацию по id' })
    @ApiResponse({ status: HttpStatus.OK, type: Organization })
    @ApiQuery({ name: 'token', type: GetOneWithTokenDto })
    @Auth(AuthType.None)
    @Get('/:id')
    getOneWithToken(
        @Param('id') id: string,
        @Query() queryDto: GetOneWithTokenDto,
    ) {
        return this.organizationsService.getOrganizationByIdWithToken(
            queryDto.token,
            +id,
        );
    }
}
