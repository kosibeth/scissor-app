import {
  Injectable,
  NotFoundException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Analytics, AnalyticsDocument } from './entities/analytics.entity';
import { Model } from 'mongoose';
import { CreateAnalyticsDto } from './dto/create-analytics.dto';

@Injectable()
export class AnalyticsService {
  private readonly logger = new Logger(AnalyticsService.name);

  constructor(
    @InjectModel(Analytics.name)
    private readonly analyticsModel: Model<AnalyticsDocument>,
  ) {}

  async trackClick(createAnalyticsDto: CreateAnalyticsDto): Promise<Analytics> {
    const { shortUrl, clickLocation } = createAnalyticsDto;

    if (!shortUrl) {
      this.logger.warn('TrackClick: Missing shortUrl');
      throw new BadRequestException('shortUrl is required');
    }

    const analytics = await this.analyticsModel.findOne({ shortUrl }).exec();
    if (analytics) {
      analytics.clickCount++;
      analytics.clickLocation.set(
        clickLocation,
        (analytics.clickLocation.get(clickLocation) || 0) + 1,
      );
      this.logger.debug(
        `TrackClick: Updated analytics for shortUrl ${shortUrl}`,
      );
      return analytics.save();
    }

    const newAnalytics = new this.analyticsModel({
      shortUrl,
      clickCount: 1,
      clickLocation: new Map([[clickLocation, 1]]),
    });
    this.logger.debug(
      `TrackClick: Created new analytics for shortUrl ${shortUrl}`,
    );
    return newAnalytics.save();
  }

  async getAnalytics(shortUrl: string): Promise<Analytics> {
    if (!shortUrl) {
      this.logger.warn('GetAnalytics: Missing shortUrl');
      throw new BadRequestException('shortUrl is required');
    }

    const analytics = await this.analyticsModel.findOne({ shortUrl }).exec();
    if (!analytics) {
      this.logger.warn(
        `GetAnalytics: Analytics not found for shortUrl ${shortUrl}`,
      );
      throw new NotFoundException(
        `Analytics not found for shortUrl ${shortUrl}`,
      );
    }

    this.logger.debug(
      `GetAnalytics: Retrieved analytics for shortUrl ${shortUrl}`,
    );
    return analytics;
  }
}
