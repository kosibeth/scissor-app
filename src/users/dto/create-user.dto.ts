import {
  IsNotEmpty,
  IsString,
  IsEmail,
  MinLength,
  Matches,
} from 'class-validator';

export class CreateUserDto {
  @IsNotEmpty()
  @IsString()
  public firstName: string;

  @IsNotEmpty()
  @IsString()
  public lastName: string;

  @IsEmail()
  public email: string;

  @IsString()
  @MinLength(10)
  @Matches(/(?=.*[A-Z])/, {
    message: 'Password must contain at least one uppercase letter',
  })
  @Matches(/(?=.*[a-z])/, {
    message: 'Password must contain at least one lowercase letter',
  })
  @Matches(/(?=.*\d)/, { message: 'Password must contain at least one digit' })
  @Matches(/(?=.*[!@#$%^&*()_+{}\[\]:;"'<>,.?~\\/-])/, {
    message: 'Password must contain at least one special character',
  })
  public password: string;
}
