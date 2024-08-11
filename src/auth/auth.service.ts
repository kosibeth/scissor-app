import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { User, UserDocument } from '../users/entities/user.entity';
import { UsersService } from 'src/users/users.service';
import { SignUpDto } from './dto/signup-auth.dto';
import { LoginDto } from './dto/login-auth.dto';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import mongoose, { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    @InjectModel(User.name) private UserModel: Model<User>,
    // private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async signUp(signUpDto: SignUpDto) {
    const { firstName, lastName, email, password } = signUpDto;

    // Check if the user already exists
    const existingUser = await this.UserModel.findOne({email: signUpDto.email});
    if (existingUser) {
      this.logger.warn(`Signup attempt with existing email: ${email}`);
      throw new ConflictException('Email already in use');
    }

    const salt = await bcrypt.genSalt(10);
    // Hash the password before saving
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create the user
    await this.UserModel.create({
      _id: new mongoose.Types.ObjectId(),
      firstName,
      lastName,
      email,
      password: hashedPassword,
      salt
    })

    // Generate JWT token
    async generateUserToken(userId){

      const accessToken = this.jwtService.sign({userId})
    }
//     const token = this.jwtService.sign({ id: newUser._id });

//     this.logger.debug(`User signed up: ${email}`);
//     return { token };
  }

//   // Login logic
  async login(loginDto: LoginDto){
    const { email, password } = loginDto;
    
    const user = await this.UserModel.findOne({email});
    if (!user) {
      throw new UnauthorizedException('Wrong email');
    }

    const isPasswordMatched = await bcrypt.compare(password, user.password);
    if (!isPasswordMatched) {
      throw new UnauthorizedException('Wrong password');
    }

    return{
      message: "Successful"
    }
  }
//     const token = this.jwtService.sign({ id: user._id });
//     return { token };
//   }
//   //     this.logger.warn(`Failed login attempt for email: ${email}`);
//   //     throw new UnauthorizedException('Invalid credentials');
//   //   }

//   //   this.logger.debug(`User logged in: ${user.email}`);
//   //   return this.jwtService.sign({ id: user._id });
//   // }

//   // async validateUser( email: string, password: string): Promise<any> {
//   //   const user = await this.userModel.findOne({ email });
//   //   if (user && (await bcrypt.compare(password, user.password))) {
//   //     return user;
//   //   }
//   //   return null;
//   // }

//   //   return user;
//   // }
}
