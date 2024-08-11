import {
  Controller,
  Post,
  Get,
  Param,
  Body,
  UseGuards,
  HttpCode,
  HttpStatus,
  NotFoundException,
  Req,
} from '@nestjs/common';
import { UrlsService } from './url.service';
import { CreateUrlDto } from './dto/create-url.dto';
import { JwtAuthGuard } from '../auth/jwt.auth.guard';
import { Request } from 'express';

@Controller('urls')
export class UrlsController {
  constructor(private readonly urlsService: UrlsService) {}

  @UseGuards(JwtAuthGuard)
  @Post('create')
  @HttpCode(HttpStatus.CREATED)
  async createUrl(@Body() createUrlDto: CreateUrlDto, @Req() req: Request) {
    const userId = req.user['id'];
    const url = await this.urlsService.createUrl(createUrlDto, userId);
    return {
      message: 'URL created successfully',
      url,
    };
  }

  @Get(':shortUrl')
  async getOriginalUrl(@Param('shortUrl') shortUrl: string) {
    const longUrl = await this.urlsService.getOriginalUrl(shortUrl);
    if (!longUrl) {
      throw new NotFoundException(`URL with shortUrl ${shortUrl} not found`);
    }
    await this.urlsService.updateClickCount(shortUrl);
    return {
      message: 'URL retrieved successfully',
      longUrl,
    };
  }

  @Get(':shortUrl/qrcode')
  async getQRCode(@Param('shortUrl') shortUrl: string) {
    const qrCode = await this.urlsService.generateQRCode(shortUrl);
    return {
      message: 'QR code generated successfully',
      qrCode,
    };
  }
}
