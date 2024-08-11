import {
  Controller,
  Post,
  Body,
  Req,
  UseGuards,
  // HttpCode,
  // HttpStatus,
  // UseGuards,
  // Req,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpDto } from './dto/signup-auth.dto';
import { LoginDto } from './dto/login-auth.dto';
import { Request } from 'express';
import { JwtAuthGuard } from './jwt.auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('/signup')
  async signUp(@Body() signupdto: SignUpDto) {
    return this.authService.signUp(signupdto);
  }

  // @UseGuards(JwtAuthGuard)
  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  a

  // @UseGuards(JwtAuthGuard)
  // @Post('validate')
  // async validateUser(@Req() req: Request) {
  //   const user = await this.authService.validateUser(req.user['id']);
  //   return {
  //     message: 'User validated',
  //     user,
  //   };
  // }
}
