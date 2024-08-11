import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export type AnalyticsDocument = HydratedDocument<Analytics>;
@Schema({ timestamps: true })
export class Analytics {
  @Prop({ required: true })
  shortUrl: string;

  @Prop({ default: 0 })
  clickCount: number;

  @Prop({ type: Map, of: Number, default: {} })
  clickLocation: Map<string, number>;
}

export const AnalyticsSchema = SchemaFactory.createForClass(Analytics);
