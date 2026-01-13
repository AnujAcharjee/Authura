import { Request } from 'express';
import { UserRole } from '@/config/database';

declare global {
  namespace Express {
    interface Request {
      user: {
        userId: string;
        role: UserRole;
      };
      requestId: string;
    }
  }
}
