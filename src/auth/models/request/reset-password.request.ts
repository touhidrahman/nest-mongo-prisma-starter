import { IsNotEmpty, MinLength } from 'class-validator';

export class ResetPasswordRequest {
  @IsNotEmpty()
  token: string;

  @IsNotEmpty()
  @MinLength(8)
  newPassword: string;
}
