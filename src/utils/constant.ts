/** User & Auth */

export const ROLES = {
  ADMIN: 'ADMIN',
  DEVELOPER: 'DEVELOPER',
  USER: 'USER',
} as const;
export type Role = (typeof ROLES)[keyof typeof ROLES];

export const GENDERS = {
  MALE: 'MALE',
  FEMALE: 'FEMALE',
  OTHER: 'OTHER',
} as const;
export type Gender = (typeof GENDERS)[keyof typeof GENDERS];

export const AUTH_PROVIDERS = {
  DEFAULT: 'DEFAULT',
  GOOGLE: 'GOOGLE',
  GITHUB: 'GITHUB',
} as const;
export type AuthProvider = (typeof AUTH_PROVIDERS)[keyof typeof AUTH_PROVIDERS];

/** OAuth */

export const OAUTH_CLIENT_TYPES = {
  PUBLIC: 'PUBLIC',
  CONFIDENTIAL: 'CONFIDENTIAL',
} as const;
export type OAuthClientType = (typeof OAUTH_CLIENT_TYPES)[keyof typeof OAUTH_CLIENT_TYPES];

export const SCOPES = {
  OPENID: 'openid',
  PROFILE: 'profile',
  EMAIL: 'email',
  AVATAR: 'avatar',
} as const;
export type Scope = (typeof SCOPES)[keyof typeof SCOPES];

/** JOSE */

export const KEY_STATUS = {
  ACTIVE: 'ACTIVE',
  RETIRED: 'RETIRED',
  REVOKED: 'REVOKED',
} as const;
export type KeyStatus = (typeof KEY_STATUS)[keyof typeof KEY_STATUS];

export const KEY_USE = {
  SIG: 'SIG',
  ENC: 'ENC',
} as const;
export type KeyUse = (typeof KEY_USE)[keyof typeof KEY_USE];

export const KEY_ALGORITHMS = {
  RS256: 'RS256',
  ES256: 'ES256',
} as const;
export type KeyAlgorithm = (typeof KEY_ALGORITHMS)[keyof typeof KEY_ALGORITHMS];

/** Crypto Algorithms */

export const CRYPTO_ALGORITHMS = {
  sha256: 'sha256',
  sha384: 'sha384',
  sha512: 'sha512',
} as const;
export type CryptoAlgorithm = (typeof CRYPTO_ALGORITHMS)[keyof typeof CRYPTO_ALGORITHMS];
