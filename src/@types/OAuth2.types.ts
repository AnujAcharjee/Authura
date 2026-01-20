import { OAuthClientType } from 'generated/prisma';

export type RegisterClientParams = {
  slug: string;
  clientType: OAuthClientType;
};

export type RegisterClientResult = {
  clientId: string;
  clientSecret: string;
};

export type UpdateRedirectsParams = {
  redirectUri: string;
  action: 'add' | 'remove';
  clientId: string;
  clientSecret: string;
};

export type AuthorizeClientParams = {
  responseType: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  nonce?: string;
  codeChallenge?: string;
  codeChallengeMethod?: 'S256';
  userId: string;
};

export type IssueTokensParams = {
  grantType: 'authorization_code';
  code: string;
  codeVerifier: string;
  clientId: string;
  clientSecret: string;
};

export type IssueTokensResult = {
  accessToken: string;
  idToken: string;
};

export type CachedClient = {
  userId: string;
  clientId: string;
  domain: string;
  clientSecretHash: string;
  scope: string[];
  nonce: string | undefined;
  codeChallenge?: string;
  codeChallengeMethod?: 'S256';
  authTime: number;
};
