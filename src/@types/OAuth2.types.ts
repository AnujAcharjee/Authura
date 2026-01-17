import { OAuthClientType } from 'generated/prisma';

export interface RegisterClientParams {
  domain: string;
  clientType: OAuthClientType;
}

export interface RegisterClientResult {
  clientId: string;
  clientSecret: string;
}

export interface UpdateRedirectsParams {
  redirectUri: string;
  action: 'add' | 'remove';
  clientId: string;
  clientSecret: string;
}

export interface AuthorizeClientParams {
  responseType: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  nonce?: string;
  codeChallenge?: string;
  codeChallengeMethod?: 'S256';
  userId: string;
}

export interface IssueTokensParams {
  grantType: 'authorization_code';
  code: string;
  codeVerifier: string;
  clientId: string;
  clientSecret: string;
}

export interface IssueTokensResult {
  accessToken: string;
  idToken: string;
}

export interface CachedClient {
  userId: string;
  clientId: string;
  domain: string;
  clientSecretHash: string;
  scope: string[];
  nonce: string | undefined;
  codeChallenge?: string;
  codeChallengeMethod?: 'S256';
  authTime: number;
}
