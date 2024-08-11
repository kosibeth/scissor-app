import { IsUrl, IsNotEmpty, IsOptional, IsNumber } from 'class-validator';

export class CreateAnalyticsDto {
  @IsUrl()
  @IsNotEmpty()
  public shortUrl: string;

  @IsOptional()
  @IsNumber()
  public clickCount: number;

  @IsOptional()
  public clickLocation: string;
}
