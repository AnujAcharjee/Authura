import { z } from 'zod';
import { OAuthClientType } from '@/config/database';

// REGISTER CLIENT
export const registerClientSchema = z.object({
  body: z.object({
    domain: z.string().min(1, 'Domain is required'),
    client_type: z.enum(OAuthClientType).optional(),
  }),
});

// UPDATE REDIRECT
export const updateRedirectSchema = z.object({
  body: z.object({
    redirect_uri: z.url('Invalid redirect_uri'),
    action: z.enum(['add', 'remove']),
    client_id: z.string().min(1, 'client_id is required'),
    client_secret: z.string().min(1, 'client_secret is required'),
  }),
});

// JWKS
export const jwksSchema = z.object({});

// AUTHORIZE
export const authorizeClientSchema = z.object({
  query: z.object({
    response_type: z.literal('code'),
    client_id: z.string().min(1, 'client_id is required'),
    redirect_uri: z.url('Invalid redirect_uri'),
    scope: z.string().min(1, 'scope is required'),
    state: z.string().optional(),
    nonce: z.string().optional(),
    code_challenge: z.string().min(43).optional(),
    code_challenge_method: z.literal('S256').optional(),
  }),
});

// TOKEN
export const issueTokensSchema = z.object({
  body: z.object({
    grant_type: z.literal('authorization_code'),
    code: z.string().min(1, 'authorization code is required'),
    client_id: z.string().min(1, 'client_id is required'),
    code_verifier: z.string().min(43).optional(),
  }),
});
