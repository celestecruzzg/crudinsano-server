import { IsEnum, IsNotEmpty, Matches } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import xss from 'xss';

export class CreateUserDto {
  @ApiProperty({ example: 'Celeste' })
  @Transform(({ value }) => xss(value))
  @IsNotEmpty()
  @Matches(/^[a-zA-ZÁÉÍÓÚáéíóúñÑ\s]+$/, {
    message: 'El nombre solo puede contener letras',
  })
  nombre: string;

  @ApiProperty({ example: 'femenino' })
  @IsEnum(['masculino', 'femenino'])
  sexo: string;
}
