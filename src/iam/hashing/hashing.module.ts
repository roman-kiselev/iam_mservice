import { Module } from '@nestjs/common';
import { BcryptService } from './bcrypt.service';
import { HashingService } from './hashing.service';

@Module({
    providers: [BcryptService],
    exports: [HashingService],
})
export class HashingModule {}
