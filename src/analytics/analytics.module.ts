import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { Analytics, AnalyticsSchema } from './entities/analytics.entity';
import { AnalyticsService } from './analytics.service';
import { AnalyticsController } from './analytics.controller';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Analytics.name, schema: AnalyticsSchema },
    ]),
  ],
  controllers: [AnalyticsController],
  providers: [AnalyticsService],
})
export class AnalyticsModule {}
