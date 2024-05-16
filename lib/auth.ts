import Credentials from "next-auth/providers/credentials";
import * as bcrypt from 'bcrypt';
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export const authOptions = {
  providers: [
    Credentials({
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "text" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials, req) {
        try {
          const res = await prisma.user.findFirst({
            where: {
              email: credentials?.email,
            },
          });

          if (res) {
            const isPasswordCorrect = await bcrypt.compare(
              credentials?.password || "",
              res.password
            );

            if (isPasswordCorrect) {
              const { id, firstName, lastName, email } = res;
              return { id: id.toString(), firstName, lastName, email };
            } else {
              return null;
            }
          } else {
            return null;
          }
        } catch (err) {
          console.log(err);
          return null; 
        }
      },
    }),
  ],
  callbacks: {
    jwt: async ({ user, token }: any) => {
    if (user) {
        token.uid = user.id;
    }
    return token;
    },
  session: ({ session, token, user }: any) => {
      if (session.user) {
          session.user.id = token.uid
      }
      return session
  }
},
};