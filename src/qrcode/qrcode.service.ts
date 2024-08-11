import { Injectable } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { InjectModel } from '@nestjs/mongoose';
import { ConfigService } from '@nestjs/config';
import { Model } from 'mongoose';
import { AxiosResponse } from 'axios';
import { Url, UrlDocument } from '../url/entities/url.entity';

@Injectable()
export class QrcodeService {
  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
    @InjectModel(Url.name) private readonly urlModel: Model<UrlDocument>,
  ) {}

  async generateQrcode(urlId: string): Promise<string> {
    const urlDocument = await this.urlModel.findById(urlId);
    if (!urlDocument) {
      throw new Error('URL not found');
    }

    const options = {
      method: 'GET',
      url: 'https://qr-code-generator20.p.rapidapi.com',
      params: {
        data: encodeURIComponent(urlDocument.longUrl),
        size: '196',
        margin: '10',
        label: 'Scissor',
        label_size: '20',
        label_alignment: 'center',
        foreground_color: '000000',
        background_color: 'FFFFFF',
      },
      headers: {
        'x-rapidapi-key': this.configService.get<string>('RAPIDAPI_KEY'),
        'x-rapidapi-host': this.configService.get<string>('RAPIDAPI_HOST'),
      },
    };

    try {
      const response: AxiosResponse<any> = await this.httpService
        .get(options.url, { params: options.params, headers: options.headers })
        .toPromise();

      const qrCodeBase64 = response.data;

      // Save the QR code to the existing URL document
      urlDocument.qrcode = qrCodeBase64;
      await urlDocument.save();

      return qrCodeBase64;
    } catch (error) {
      console.error('Error generating QR code:', error);
      throw new Error('Failed to generate QR code');
    }
  }
}
