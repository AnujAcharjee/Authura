import { UserRole } from '@/config/database';

export interface SignupParams {
  name: string;
  email: string;
  password: string;
}

export interface SignupResult {
  id: string;
  email: string;
  name: string;
  role: UserRole;
  createdAt: Date;
}

export interface VerifyEmailResult {
  identitySessionId: string;
  activeSessionId: string;
}

export interface SigninParams {
  email: string;
  password: string;
}

export interface SigninResult {
  mfaEnabled: boolean;
  identitySessionId: string | undefined;
  activeSessionId: string | undefined;
}

export interface VerifySignInResult {
  identitySessionId: string;
  activeSessionId: string;
}
