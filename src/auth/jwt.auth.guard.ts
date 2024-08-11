import {
  Injectable,
  ExecutionContext,
  UnauthorizedException,
  Logger,
  ForbiddenException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  private readonly logger = new Logger(JwtAuthGuard.name);

  canActivate(context: ExecutionContext) {
    // Log the context of the request for better traceability
    const request = context.switchToHttp().getRequest();
    const { method, url } = request;
    this.logger.debug(`Validating request for ${method} ${url}`);

    // Check for additional conditions if needed before calling the parent method
    return super.canActivate(context);
  }

  handleRequest(err, user) {
    // If there's an error during the authentication process
    if (err) {
      this.logger.error(`Authentication error: ${err.message}`);
      throw new UnauthorizedException('Authentication failed');
    }

    // If no user was found or the token is invalid/expired
    if (!user) {
      this.logger.warn('Unauthorized access attempt detected');
      throw new UnauthorizedException('Invalid or expired token');
    }

    // Optionally, add additional checks based on the user object
    if (!user.isActive) {
      this.logger.warn(`User ${user.email} attempted access but is inactive`);
      throw new ForbiddenException('Your account is inactive');
    }

    this.logger.debug(`User ${user.email} successfully authenticated`);
    return user;
  }
}
