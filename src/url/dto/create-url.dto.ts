import {
  IsString,
  IsUrl,
  IsOptional,
  Length,
  IsNotEmpty,
} from 'class-validator';

export class CreateUrlDto {
  @IsUrl()
  @IsNotEmpty()
  public longUrl: string;

  @IsString()
  @IsOptional()
  @Length(1, 50)
  public customUrl: string;

  @IsString()
  @IsOptional()
  public qrcode: string;
}
