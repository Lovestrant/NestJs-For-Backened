import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2'
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService){}

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
    return user;
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
         return user;
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
}