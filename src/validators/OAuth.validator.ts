import { z } from 'zod';
import { CRYPTO_ALGORITHMS, type CryptoAlgorithm, type Scope } from '../utils/constant.js';

export class OAuthZSchema {
  static authorizeClientSchema = z.object({
    query: z.object({
      response_type: z.literal('code'),
      client_id: z.string().min(1, 'client_id is required'),
      redirect_uri: z.url('Invalid redirect_uri'),
      scope: z.string().min(1, 'Scope is required'),
      state: z.string().optional(),
      nonce: z.string().optional(),
      code_challenge: z.string().min(43).optional(),
      code_challenge_algo: z
        .enum(Object.values(CRYPTO_ALGORITHMS) as [CryptoAlgorithm, ...CryptoAlgorithm[]])
        .optional(),
    }),
  });

  static authConsentSchema = z.object({
    body: z.object({
      request_id: z.uuid('request_id must be a valid UUID'),
      redirect_uri: z.url('Invalid redirect_uri').optional(),
      state: z.string().optional(),
      decision: z.enum(['approve', 'deny'], {
        message: 'decision must be "approve" or "deny"',
      }),
    }),
  });

  static issueTokensSchema = z.object({
    body: z.object({
      grant_type: z.literal('authorization_code'),
      code: z.string().min(1, 'authorization code is required'),
      client_id: z.string().min(1, 'client_id is required'),
      code_verifier: z.string().min(43).optional(),
    }),
  });

  static updateConsentSchema = z.object({
    body: z.object({
      clientId: z.uuid('clientId must be a valid UUID'),
    }),
  });
}
