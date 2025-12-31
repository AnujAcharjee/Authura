import * as dotenv from 'dotenv';
dotenv.config({ path: '.env.development' });

import prisma from '../src/config/database';
import { UserRole } from '../generated/prisma/enums';
import bcrypt from 'bcrypt';

async function main() {
  console.log('🌱 Running development seed...');

  await prisma.user.deleteMany();

  const password = await bcrypt.hash('Password123!', 10);

  const users = await prisma.user.createMany({
    data: [
      {
        name: 'John Doe',
        email: 'john@example.com',
        password,
        role: UserRole.ADMIN,
      },
      {
        name: 'Jane Smith',
        email: 'jane@example.com',
        password,
        role: UserRole.USER,
      },
      {
        name: 'Bob Johnson',
        email: 'bob@example.com',
        password,
        role: UserRole.USER,
      },
    ],
  });

  console.log('✅ Development seed completed', users);
}

main()
  .catch((e) => {
    console.error("❌ Dev seed failed", e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });