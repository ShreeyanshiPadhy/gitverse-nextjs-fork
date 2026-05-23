import { sanitizeError } from "@/lib/middleware";
import { NextRequest, NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import prisma from "@/lib/prisma";
import { generateToken } from "@/lib/auth";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { email, password, name } = body;

    // Validation
    if (!email || !password || !name) {
      return NextResponse.json(
        { error: "Email, password, and name are required" },
        { status: 400 }
      );
    }

    if (password.length < 6) {
      return NextResponse.json(
        { error: "Password must be at least 6 characters" },
        { status: 400 }
      );
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const txResult = await prisma.$transaction(async (tx) => {
      // Check if user already exists
      const existingUser = await tx.user.findUnique({
        where: { email },
      });

      if (existingUser) {
        const isGoogleOnly =
          !existingUser.passwordHash &&
          (await tx.account.count({
            where: { userId: existingUser.id, provider: "google" },
          })) > 0;

        return { error: isGoogleOnly ? "GOOGLE_ONLY" : "USER_EXISTS" };
      }

      // Create user
      const createdUser = await tx.user.create({
        data: {
          email,
          passwordHash: hashedPassword,
          name,
        },
      });

      return { user: createdUser };
    });

    if ("error" in txResult) {
      if (txResult.error === "GOOGLE_ONLY") {
        return NextResponse.json(
          { error: "Email already exists. Please sign in with Google." },
          { status: 409 }
        );
      }

      return NextResponse.json(
        { error: "User with this email already exists" },
        { status: 409 }
      );
    }

    const user = txResult.user;

    // Generate JWT token
    const token = generateToken({ userId: user.id, email: user.email });

    return NextResponse.json(
      {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          avatarUrl: (user as any).image,
        },
        token,
      },
      { status: 201 }
    );
  } catch (error: any) {
    if (error?.code === "P2002") {
      return NextResponse.json(
        { error: "User with this email already exists" },
        { status: 409 }
      );
    }

    console.error("Signup error:", sanitizeError(error));
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
