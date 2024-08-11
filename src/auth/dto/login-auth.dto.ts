import { IsString, IsEmail, IsNotEmpty, Length } from 'class-validator';

export class LoginDto {
  @IsEmail({}, { message: 'Enter correct email' })
  @IsNotEmpty()
  @Length(10, 100)
  readonly email: string;

  @IsString()
  @IsNotEmpty()
  @Length(10, 100)
  readonly password: string;
}
