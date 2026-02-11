import { z } from 'zod';
import {
  OAUTH_CLIENT_TYPES,
  OAUTH_CLIENT_ENVIRONMENTS,
  type OAuthClientType,
  type OAuthClientEnvironment,
} from '../utils/constant.js';
import { UtilFields } from './util.fields.js';

export class ClientZSchema {
  static addClientSchema = z.object({
    body: z.object({
      name: z.string(),
      slug: z.string().min(1, 'Domain is required'),
      client_type: z
        .enum(Object.values(OAUTH_CLIENT_TYPES) as [OAuthClientType, ...OAuthClientType[]])
        .optional(),
      client_environment: z
        .enum(
          Object.values(OAUTH_CLIENT_ENVIRONMENTS) as [
            OAuthClientEnvironment,
            ...OAuthClientEnvironment[],
          ],
        )
        .optional(),
      redirect_uri: UtilFields.redirectUriField,
    }),
  });

  static manageRedirectsSchema = z.object({
    params: z.object({
      client_id: UtilFields.clientIdField,
    }),
    body: z.object({
      redirect_uri: UtilFields.redirectUriField,
      action: z
        .enum(['add', 'del'])
        .refine((v) => v === 'add' || v === 'del', "Action must be either 'add' or 'del'."),
    }),
  });

  static clientIdSchema = z.object({
    params: z.object({
      client_id: UtilFields.clientIdField,
    }),
  });

  static rotateSecretSchema = z.object({
    body: z.object({
      client_id: UtilFields.clientIdField,
    }),
  });

  static updateEnvironmentSchema = z.object({
    params: z.object({
      client_id: UtilFields.clientIdField,
    }),
    body: z.object({
      environment: z.enum(
        Object.values(OAUTH_CLIENT_ENVIRONMENTS) as [
          OAuthClientEnvironment,
          ...OAuthClientEnvironment[],
        ],
      ),
    }),
  });

  // JWKS

  static jwksSchema = z.object({
    params: {
      client_id: UtilFields.clientIdField,
    },
  });
}
