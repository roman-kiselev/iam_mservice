import { ApiProperty } from '@nestjs/swagger';

export class TokensResponse {
    @ApiProperty({
        example: 'AsdkkdkafF.fdsfsdfaAf.dfsdfdsg',
        description: 'Описание что с ним делать',
        title: 'Access token',
    })
    accessToken: string;
    @ApiProperty({
        example: 'AsdkkdkafF.fdsfsdfaAf.dfsdfdsg',
        description: 'Описание что с ним делать',
        title: 'refresh token',
    })
    refreshToken: string;
}
