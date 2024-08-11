import {
  Controller,
  Post,
  Param,
  HttpStatus,
  HttpException,
} from '@nestjs/common';
import { QrcodeService } from './qrcode.service';

@Controller('qrcode')
export class QrcodeController {
  constructor(private readonly qrcodeService: QrcodeService) {}

  @Post(':urlId')
  async generateQrcode(@Param('urlId') urlId: string): Promise<string> {
    try {
      return await this.qrcodeService.generateQrcode(urlId);
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.BAD_REQUEST);
    }
  }
}
