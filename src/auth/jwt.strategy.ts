import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
// import { AuthService } from './auth.service';
import { UsersService } from 'src/users/users.service';
import { User } from 'src/users/entities/user.entity';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  private readonly logger = new Logger(JwtStrategy.name);

  constructor(
    private readonly usersService: UsersService
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_SECRET,
      ignoreExpiration: false,
    });
  }

  async validate(payload: { email: string }): Promise<User> {
    this.logger.debug('Validating JWT payload:', payload);

    try {
      const user = await this.usersService.findByEmail(payload.email);

      if (!user) {
        this.logger.warn('User not found for JWT payload:', payload);
        throw new UnauthorizedException('Invalid token');
      }

      return user;
    } catch (error) {
      this.logger.error('Error during user validation:', error.stack);
      throw new UnauthorizedException('Invalid token');
    }
  }
}
