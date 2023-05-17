import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2'
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class AuthService {
 constructor(private prisma: PrismaService,
        private jwt: JwtService, 
        private config: ConfigService){}

   async signin(dto: AuthDto) {
    // Find User by email
    const user = await this.prisma.user.findUnique({
        where: {
            email: dto.email,
        }
    });
    //If user does not exist throw exception
    if(!user) {
        throw new ForbiddenException(
            'credentials incorrect'
        )
    }
    //Compare password
    const pwMatches = await argon.verify(
        user.harsh,
        dto.password
    )
    //If password is Incorrect throw exception
    delete user.harsh;
    //Send back the user
    return this.signToken(user.id, user.email);
    }

    async signup(dto: AuthDto) {
        // Generate the password harsh
        const harsh = await argon.hash(dto.password);
        //Save the new user into db
        try{
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    harsh,
                },
                select: {
                    id: true,
                    email: true
                }
            });

         //Return the saved user
         return this.signToken(user.id, user.email);

        }catch(error) {
         if(error instanceof PrismaClientKnownRequestError) {
          if(error.code === 'p2002') {
            throw new ForbiddenException(
                'credentials Taken'
            )
          }
         } throw error
        }
    }

    async signToken(userId: number, email: string): Promise<String> {
        const payload = {
            sub: userId,
            email
        }
        const secret = this.config.get('JWT_SECRET')

        
        return this.jwt.signAsync(payload, {
            expiresIn: '15m',
            secret: secret
        })
    }
}