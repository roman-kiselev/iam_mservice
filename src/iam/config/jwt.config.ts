import { registerAs } from '@nestjs/config';

export default registerAs('jwt', () => {
    return {
        secret: process.env.JWT_SECRET,
        audience: process.env.JWT_AUDIENCE,
        issuer: process.env.JWT_ISSUER,
        accessTtl: process.env.JWT_ACCESS_TTL,
        refreshTtl: process.env.JWT_REFRESH_TTL,
    };
});
