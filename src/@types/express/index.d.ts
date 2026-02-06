import type { Request } from 'express';
import type { Role } from '@/utils/constant';

declare global {
  namespace Express {
    interface Request {
      user: {
        id: string;
        roles: Role[];
      };
      client: {
        id: string;
        userId: string;
        scopes: Scope[];
      };
      requestId: string;
    }
  }
}
