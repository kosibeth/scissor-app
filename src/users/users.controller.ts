import {
  Controller,
  Post,
  Get,
  Put,
  Param,
  Body,
  HttpCode,
  HttpStatus,
  NotFoundException,
  BadRequestException,
  UseGuards,
  Logger,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { JwtAuthGuard } from '../auth/jwt.auth.guard';

@Controller('users')
export class UsersController {
  private readonly logger = new Logger(UsersController.name);

  constructor(private readonly usersService: UsersService) {}

  @Post()
  async createUser(@Body() createUserDto: CreateUserDto) {
    try {
      this.logger.log(
        `Request to create user with email: ${createUserDto.email}`,
      );
      const user = await this.usersService.create(createUserDto);
      return {
        message: 'User created successfully',
        user,
      };
    } catch (error) {
      this.logger.error(`Failed to create user: ${error.message}`);
      throw new BadRequestException('Failed to create user');
    }
  }

  // Get user by Id
  @Get(':id')
  @UseGuards(JwtAuthGuard)
  async getUserById(@Param('id') id: string) {
    try {
      this.logger.debug(`Request to get user with ID: ${id}`);
      const user = await this.usersService.findUserById(id);
      return {
        message: 'User retrieved successfully',
        user,
      };
    } catch (error) {
      this.logger.error(`Failed to get user by ID ${id}: ${error.message}`);
      throw new NotFoundException(`User with ID ${id} not found`);
    }
  }

  // Update user by Id
  @Put(':id')
  @UseGuards(JwtAuthGuard)
  async updateUser(
    @Param('id') id: string,
    @Body() updateUserDto: UpdateUserDto,
  ) {
    try {
      this.logger.debug(`Request to update user with ID: ${id}`);
      const updatedUser = await this.usersService.updateUser(id, updateUserDto);
      return {
        message: 'User updated successfully',
        user: updatedUser,
      };
    } catch (error) {
      this.logger.error(`Failed to update user by ID ${id}: ${error.message}`);
      throw new NotFoundException(`User with ID ${id} not found`);
    }
  }
}
