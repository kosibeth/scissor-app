import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { MongooseModule } from '@nestjs/mongoose';
import { QrcodeService } from './qrcode.service';
import { QrcodeController } from './qrcode.controller';
import { Url, UrlSchema } from '../url/entities/url.entity';

@Module({
  imports: [
    HttpModule,
    MongooseModule.forFeature([{ name: Url.name, schema: UrlSchema }]),
  ],
  controllers: [QrcodeController],
  providers: [QrcodeService],
  exports: [QrcodeService],
})
export class QrcodeModule {}
