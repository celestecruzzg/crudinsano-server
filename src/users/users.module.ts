import { Module } from '@nestjs/common';
import { UserService } from './users.service';
import { UserController } from './users.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]), // 🔥 ESTA LÍNEA ES LA QUE FALTA
  ],
  controllers: [UserController],
  providers: [UserService],
})
export class UserModule {}