import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export type UrlDocument = HydratedDocument<Url>;
@Schema({ timestamps: true })
export class Url {
  @Prop({ required: true })
  shortUrl: string;

  @Prop({ required: true })
  longUrl: string;

  @Prop()
  customUrl: string;

  @Prop({ required: true })
  userId: string;

  @Prop({ type: Date, default: Date.now })
  createdAt: Date;

  @Prop({ required: true })
  qrcode: string;

  @Prop({ default: 0 })
  clickCount: number;
}

export const UrlSchema = SchemaFactory.createForClass(Url);
