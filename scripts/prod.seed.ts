import prisma from '../src/config/database';
import { UserRole } from '../generated/prisma/enums';
import bcrypt from "bcrypt";

async function main() {
  const adminEmail = process.env.INIT_ADMIN_EMAIL;
  const adminPassword = process.env.INIT_ADMIN_PASSWORD;

  if (!adminEmail || !adminPassword) {
    throw new Error("INIT_ADMIN_EMAIL and INIT_ADMIN_PASSWORD are required");
  }

  const userCount = await prisma.user.count();

  if (userCount > 0) {
    console.log("Skipping production seed — users already exist");
    return;
  }

  const hashedPassword = await bcrypt.hash(adminPassword, 12);

  const admin = await prisma.user.create({
    data: {
      name: "System Administrator",
      email: adminEmail,
      password: hashedPassword,
      role: UserRole.ADMIN,
      emailVerifiedAt: new Date(),
    },
  });

  console.log("✅ Production admin created:", {
    id: admin.id,
    email: admin.email,
  });
}

main()
  .catch((e) => {
    console.error("❌ Production seed failed", e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
