import { Module } from '@nestjs/common';
import { CacheModule } from '@nestjs/cache-manager';
import { MongooseModule } from '@nestjs/mongoose';
import { Url, UrlSchema } from './entities/url.entity';
import { UrlsService } from './url.service';
import { UrlsController } from './url.controller';
import { QrcodeModule } from '../qrcode/qrcode.module';
import { RateLimiterModule } from 'nestjs-rate-limiter';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Url.name, schema: UrlSchema }]),
    CacheModule.register({ ttl: 5, max: 10 }),
    QrcodeModule,
    RateLimiterModule,
  ],
  controllers: [UrlsController],
  providers: [UrlsService],
})
export class UrlsModule {}
