import {
  Injectable,
  NotFoundException,
  BadRequestException,
  Inject,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Url, UrlDocument } from './entities/url.entity';
import { CreateUrlDto } from './dto/create-url.dto';
import { QrcodeService } from '../qrcode/qrcode.service';
import { Model } from 'mongoose';
import { Cache } from 'cache-manager';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import * as crypto from 'crypto';

@Injectable()
export class UrlsService {
  constructor(
    @InjectModel(Url.name) private readonly urlModel: Model<UrlDocument>,
    private readonly qrcodeService: QrcodeService,
    @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
  ) {}

  private generateShortUrl(): string {
    return crypto.randomBytes(6).toString('hex');
  }

  async createUrl(createUrlDto: CreateUrlDto, userId: string): Promise<Url> {
    const { longUrl, customUrl } = createUrlDto;
    const shortUrl = customUrl || this.generateShortUrl();

    const existingUrl = await this.urlModel.findOne({ shortUrl }).exec();
    if (existingUrl) {
      throw new BadRequestException('Custom URL already exists');
    }

    const createdUrl = new this.urlModel({ longUrl, shortUrl, userId });
    await createdUrl.save();
    await this.cacheManager.set(shortUrl, longUrl);

    return createdUrl;
  }

  async findUrlByShortUrl(shortUrl: string): Promise<Url> {
    const cachedUrl = await this.cacheManager.get<string>(shortUrl);
    if (cachedUrl) {
      return this.urlModel.findOne({ shortUrl }).exec();
    }

    const url = await this.urlModel.findOne({ shortUrl }).exec();
    if (!url) {
      throw new NotFoundException(`URL with shortUrl ${shortUrl} not found`);
    }

    await this.cacheManager.set(shortUrl, url.longUrl);
    return url;
  }

  async getOriginalUrl(shortUrl: string): Promise<string> {
    const cachedUrl = await this.cacheManager.get<string>(shortUrl);
    if (cachedUrl) {
      return cachedUrl;
    }

    const url = await this.findUrlByShortUrl(shortUrl);
    return url.longUrl;
  }

  async updateClickCount(shortUrl: string): Promise<void> {
    const url = await this.findUrlByShortUrl(shortUrl);
    await this.urlModel
      .updateOne({ shortUrl }, { $inc: { clickCount: 1 } })
      .exec();
  }

  async generateQRCode(shortUrl: string): Promise<string> {
    return this.qrcodeService.generateQrcode(shortUrl);
  }
}
