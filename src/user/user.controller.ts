import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Param,
  Put,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { AuthUser } from '../auth/auth-user';
import { UpdateUserRequest } from './models';
import { Usr } from './user.decorator';
import { UserService } from './user.service';

@ApiTags('users')
@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @ApiBearerAuth()
  @Put(':id')
  @HttpCode(HttpStatus.OK)
  @UseGuards(AuthGuard())
  async updateUser(
    @Param('id') id: string,
      @Body() updateRequest: UpdateUserRequest,
      @Usr() user: AuthUser,
  ): Promise<void> {
    if (id !== user.id) {
      throw new UnauthorizedException();
    }
    await this.userService.updateUser(id, updateRequest);
  }
}
