import { Injectable, NotFoundException, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from './entities/user.entity';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);

  constructor(
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    const { email } = createUserDto;
    const existingUser = await this.userModel.findOne({ email });
    if (existingUser) {
      throw new Error('User already exists');
    }

    const createdUser = new this.userModel(createUserDto);
    return createdUser.save();
  }

  // async createUser(createUserDto: CreateUserDto): Promise<User> {
  //   const newUser = new this.userModel(createUserDto);
  //   this.logger.debug(`Creating a new user with email: ${createUserDto.email}`);
  //   return newUser.save();
  // }

  async findUserById(id: string): Promise<User> {
    const user = await this.userModel.findById(id).exec();
    if (!user) {
      this.logger.warn(`User with ID ${id} not found`);
      throw new NotFoundException(`User with ID ${id} not found`);
    }
    this.logger.debug(`User with ID ${id} found`);
    return user;
  }

  async findByEmail(email: string): Promise<User> {
    const user = await this.userModel.findOne({ email }).exec();
    if (!user) {
      this.logger.warn(`User with email ${email} not found`);
      throw new NotFoundException(`User with email ${email} not found`);
    }
    this.logger.debug(`User with email ${email} found`);
    return user;
  }

  async updateUser(id: string, updateUserDto: UpdateUserDto): Promise<User> {
    const updatedUser = await this.userModel
      .findByIdAndUpdate(id, updateUserDto, { new: true })
      .exec();
    if (!updatedUser) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }
    this.logger.debug(`Updating user with ID ${id}`);
    return updatedUser;
  }
}
