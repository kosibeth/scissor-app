import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  BadRequestException,
} from '@nestjs/common';
import { AnalyticsService } from './analytics.service';
import { Analytics } from './entities/analytics.entity';
import { CreateAnalyticsDto } from './dto/create-analytics.dto';

@Controller('analytics')
export class AnalyticsController {
  constructor(private readonly analyticsService: AnalyticsService) {}

  @Post('track')
  async trackClick(
    @Body() createAnalyticsDto: CreateAnalyticsDto,
  ): Promise<Analytics> {
    if (!createAnalyticsDto.shortUrl || !createAnalyticsDto.clickLocation) {
      throw new BadRequestException('shortUrl and clickLocation are required');
    }
    return this.analyticsService.trackClick(createAnalyticsDto);
  }

  @Get(':shortUrl')
  async getAnalytics(@Param('shortUrl') shortUrl: string): Promise<Analytics> {
    if (!shortUrl) {
      throw new BadRequestException('shortUrl is required');
    }
    return this.analyticsService.getAnalytics(shortUrl);
  }
}
