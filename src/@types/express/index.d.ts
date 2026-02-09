import type { Role, Scope } from '../../utils/constant.js';

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
