import { ENV } from '@/config/env';
import { AppError } from '@/utils/appError';
import { ErrorCode } from '@/utils/errorCodes';
import jwt from 'jsonwebtoken';

export class Jwt {
  private privateKey: string;
  private publicKey: string;

  constructor() {
    this.privateKey = ENV.JWT_PRIVATE_KEY!;
    this.publicKey = ENV.JWT_PUBLIC_KEY!;
  }

  createSignedJwt(payload: any): string {
    try {
      return jwt.sign(payload, this.privateKey, {
        algorithm: 'RS256',
        expiresIn: '10m',
      });
    } catch (error) {
      throw new AppError('Jwt:creteSignedJwt ERROR', 500, ErrorCode.JWT_ERROR, false, error);
    }
  }

  verifyJwt(token: string) {
    try {
      return jwt.verify(token, this.publicKey, {
        algorithms: ['RS256'],
      });
    } catch (error) {
      throw new AppError('Jwt:verifyJwt ERROR', 401, ErrorCode.JWT_ERROR, false, error);
    }
  }
}
