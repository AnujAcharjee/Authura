import { UserRole } from '@/config/database';

export type SignupParams = {
  name: string;
  email: string;
  password: string;
};

export type SignupResult = {
  id: string;
  email: string;
  name: string;
  role: UserRole;
  createdAt: Date;
};

export type VerifyEmailResult = {
  identitySessionId: string;
  activeSessionId: string;
};

export type SigninParams = {
  email: string;
  password: string;
};

export type SigninResult = {
  id: string;
  email: string;
  mfaEnabled: boolean;
  identitySessionId: string | undefined;
  activeSessionId: string | undefined;
};

export type VerifySignInResult = {
  id: string;
  email: string;
  identitySessionId: string;
  activeSessionId: string;
};
