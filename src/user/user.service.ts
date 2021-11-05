import { ConflictException, Injectable, Logger } from '@nestjs/common';
import { AuthUser } from '../auth/auth-user';
import { PrismaService } from '../common/services/prisma.service';
import { UpdateUserRequest, UserResponse } from './models';

@Injectable()
export class UserService {
  constructor(private readonly prisma: PrismaService) {}

  public async getUserEntityById(id: string): Promise<AuthUser | null> {
    return this.prisma.user.findUnique({
      where: { id },
    });
  }

  public async getUserEntityByUsername(
    username: string,
  ): Promise<AuthUser | null> {
    const normalizedUsername = username.toLowerCase();
    return this.prisma.user.findUnique({
      where: { username: normalizedUsername },
    });
  }

  async updateUser(
    userId: string,
    updateRequest: UpdateUserRequest,
  ): Promise<UserResponse> {
    try {
      const updatedUser = await this.prisma.user.update({
        where: { id: userId },
        data: {
          ...updateRequest,
          birthDate:
            updateRequest.birthDate !== null
            && updateRequest.birthDate !== undefined
              ? new Date(updateRequest.birthDate)
              : updateRequest.birthDate,
        },
      });

      return UserResponse.fromUserEntity(updatedUser);
    } catch (err) {
      Logger.error(JSON.stringify(err));
      throw new ConflictException();
    }
  }
}
