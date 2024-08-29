import { ForbiddenException, Injectable, Req } from '@nestjs/common';
import { User, BookMark } from '@prisma/client';
import { Request } from 'express';
import { AuthDto } from './dto/auth.dto';
import * as argon from 'argon2';
import { PrismaService } from 'src/prisma/prisma.service';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async login(dto: AuthDto) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) throw new ForbiddenException('Credentials Incorrect');

    // compare password

    const passwordMatches = await argon.verify(user.hash, dto.password);
    if (!passwordMatches) throw new ForbiddenException('Credentials Incorrect');

    delete user.hash;
    return user;
  }
  async singup(dto: AuthDto) {
    try {
      // generate password hash
      const hash = await argon.hash(dto.password);
      // save new user in db
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
        // this will onnly return what yoi want to show
        select: {
          id: true,
          createdAt: true,
          email: true,
        },
      });
      // or
      // delete user.hash
      // return new user
      return user;
    } catch (err) {
      if (err instanceof PrismaClientKnownRequestError) {
        if (err.code === 'P2002') {
          throw new ForbiddenException('Credentials Taken');
        }
      }
      throw err;
    }
  }
}
