import prisma from '@/config/database';
import redis from '@/config/redis';
import { AppError } from '@/utils/appError';
import { ErrorCode } from '@/utils/errorCodes';
import { AppCrypto } from '@/utils/crypto';
import { ENV } from '@/config/env';
import { OAUTH_CLIENT_TYPES, CRYPTO_ALGORITHMS, type OAuthClientType } from '@/utils/constant';

export type ClientView = {
  id: string;
  name: string;
  domain: string;
  clientType: OAuthClientType;
  enforcePKCE: boolean;
  redirectURIs: string[];
  isActive: boolean;
  revokedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
};

export type AllClientsView = {
  id: string;
  name: string;
  isActive: boolean;
};

export interface ClientUpdateInput {
  redirectURIs?: string[];
  clientSecretHash?: string;
  isActive?: boolean;
  revokedAt?: Date;
}

export class ClientService {
  private readonly clientCacheEX = ENV.NODE_ENV === 'production' ? ENV.CLIENT_CACHE_EX : 15 * 60;
  private readonly clientSecretKey = ENV.CLIENT_SECRET_KEY;
  private clientCacheKey = (clientId: string): string => `client:${clientId}`;

  async generateClientSecret() {
    const clientSecret = AppCrypto.randomToken(48);
    const clientSecretHash = AppCrypto.hmac(
      clientSecret,
      this.clientSecretKey,
      CRYPTO_ALGORITHMS.sha256,
      'base64url',
    );
    return { clientSecret, clientSecretHash };
  }

  getClientDomain(slug: string): string {
    return `https://${slug}.authura.com`;
  }

  isValidSlug(slug: string): boolean {
    if (!slug) return false;

    const normalized = slug.trim().toLowerCase();

    // Length rules (DNS label rules)
    if (normalized.length < 3 || normalized.length > 63) return false;

    // Only lowercase letters, numbers, hyphens
    if (!/^[a-z0-9-]+$/.test(normalized)) return false;

    // Cannot start or end with hyphen
    if (normalized.startsWith('-') || normalized.endsWith('-')) return false;

    // Must start with a letter (Auth0 rule – optional but recommended)
    if (!/^[a-z]/.test(normalized)) return false;

    // Must not contain consecutive hyphens
    if (normalized.includes('--')) return false;

    // Reserved / blocked names
    const reserved = new Set([
      'www',
      'api',
      'admin',
      'auth',
      'login',
      'oauth',
      'id',
      'internal',
      'local',
      'localhost',
      'root',
      'support',
      'help',
    ]);

    return !reserved.has(normalized);
  }

  normalizeAndValidateURI(uri: string): string {
    let url: URL;

    try {
      url = new URL(uri);
    } catch {
      throw new AppError('Invalid URI format', 400, ErrorCode.INVALID_REDIRECT_URI);
    }

    if (ENV.NODE_ENV === 'production' && url.protocol !== 'https:' && url.hostname !== 'localhost') {
      throw new AppError('URI must use HTTPS', 400, ErrorCode.INVALID_REDIRECT_URI);
    }

    if (uri.includes('*')) {
      throw new AppError('Wildcard URIs are not allowed', 400, ErrorCode.INVALID_REDIRECT_URI);
    }

    return url.toString();
  }

  // -------------- VERIFY CLIENT ----------------

  async verifyClient(input: { clientId: string; clientSecret: string }) {
    const client = await prisma.oAuthClient.findUnique({
      where: { id: input.clientId },
      select: {
        id: true,
        clientType: true,
        clientSecretHash: true,
        isActive: true,
        revokedAt: true,
        enforcePKCE: true,
        redirectURIs: true,
      },
    });

    if (!client || client.clientType !== OAUTH_CLIENT_TYPES.CONFIDENTIAL) {
      throw new AppError('Invalid client', 401, ErrorCode.INVALID_CLIENT);
    }

    const derived = AppCrypto.hmac(
      input.clientSecret,
      this.clientSecretKey,
      CRYPTO_ALGORITHMS.sha256,
      'base64url',
    );
    const ok = AppCrypto.timingSafeCompare(derived, client.clientSecretHash!, 'hex');
    if (!ok) {
      throw new AppError('Invalid client', 401, ErrorCode.INVALID_CLIENT);
    }

    const { clientSecretHash: _ignored, ...safeClient } = client;
    return { ...safeClient };
  }

  // ---------------- CREATE CLIENT ----------------

  async createClient(input: {
    userId: string;
    name: string;
    domain: string;
    clientType: OAuthClientType;
    redirectURI: string; // enforce ONE at creation
  }) {
    const redirectURI = this.normalizeAndValidateURI(input.redirectURI);

    const { clientSecret, clientSecretHash } =
      input.clientType === OAUTH_CLIENT_TYPES.CONFIDENTIAL ?
        await this.generateClientSecret()
      : { clientSecret: null, clientSecretHash: null };

    const client = await prisma.oAuthClient.create({
      data: {
        userId: input.userId,
        name: input.name,
        domain: input.domain,
        clientType: input.clientType,
        clientSecretHash,
        enforcePKCE: true,
        redirectURIs: [redirectURI],
        isActive: true,
      },
    });

    const { clientSecretHash: _ignored, ...safeClient } = client;
    return {
      ...safeClient,
      clientSecret,
    };
  }

  // -------- GET CLIENT --------

  async getClient(clientId: string): Promise<ClientView> {
    const cached = await redis.get(this.clientCacheKey(clientId));
    if (cached) {
      return JSON.parse(cached);
    }

    const client = await prisma.oAuthClient.findUnique({
      where: { id: clientId },
      select: {
        id: true,
        name: true,
        domain: true,
        clientType: true,
        enforcePKCE: true,
        redirectURIs: true,
        isActive: true,
        revokedAt: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!client) {
      throw new AppError('Client not found', 404, ErrorCode.NOT_FOUND);
    }

    await redis.set(this.clientCacheKey(clientId), JSON.stringify(client), 'EX', this.clientCacheEX);
    return client;
  }

  // -------- UPDATE --------
  async update(clientId: string, updates: ClientUpdateInput): Promise<ClientView> {
    if (Object.keys(updates).length === 0) {
      throw new AppError('No updates provided', 400, ErrorCode.INVALID_GRANT);
    }

    const client = await prisma.oAuthClient.update({
      where: { id: clientId },
      data: {
        ...(updates.redirectURIs !== undefined && { redirectURIs: updates.redirectURIs }),
        ...(updates.clientSecretHash !== undefined && { clientSecretHash: updates.clientSecretHash }),
        ...(updates.isActive !== undefined && { isActive: updates.isActive }),
        ...(updates.revokedAt !== undefined && { revokedAt: updates.revokedAt }),
      },
      select: {
        id: true,
        name: true,
        domain: true,
        clientType: true,
        enforcePKCE: true,
        redirectURIs: true,
        isActive: true,
        revokedAt: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!client) {
      throw new AppError('Client not found', 404, ErrorCode.NOT_FOUND);
    }

    await redis.del(this.clientCacheKey(clientId));
    return client;
  }

  // -------- ADD REDIRECT URI --------

  async addRedirectURI(input: { clientId: string; normalizedURI: string; existingRedirectURIs: string[] }) {
    const updated = [...input.existingRedirectURIs, input.normalizedURI];

    await this.update(input.clientId, { redirectURIs: updated });

    await redis.del(this.clientCacheKey(input.clientId));
    return { redirectURI: input.normalizedURI, added: true };
  }

  // -------- DELETE REDIRECT URI --------

  async deleteRedirectURI(input: {
    clientId: string;
    normalizedURI: string;
    existingRedirectURIs: string[];
  }) {
    const updated = input.existingRedirectURIs.filter((u) => u !== input.normalizedURI);

    await this.update(input.clientId, { redirectURIs: updated });

    await redis.del(this.clientCacheKey(input.clientId));
    return { redirectURI: input.normalizedURI, removed: true };
  }

  // -------- DELETE --------

  async delete(clientId: string) {
    const deleted = await prisma.oAuthClient.deleteMany({
      where: { id: clientId },
    });

    if (deleted.count === 0) {
      throw new AppError('Client not found', 404, ErrorCode.NOT_FOUND);
    }

    await redis.del(this.clientCacheKey(clientId));
  }

  // -------- ACTIVATE --------
  async activate(clientId: string) {
    await this.update(clientId, { isActive: true, revokedAt: undefined });
  }

  // ---------------- ROTATE SECRET ----------------

  async rotateClientSecret(clientId: string) {
    const { clientSecret, clientSecretHash } = await this.generateClientSecret();

    await this.update(clientId, { clientSecretHash });

    await redis.del(this.clientCacheKey(clientId));
    return { clientSecret };
  }

  // -------- GET ALL CLIENTS FOR A USER --------

  async getAllClientsForUser(userId: string): Promise<AllClientsView[]> {
    return prisma.oAuthClient.findMany({
      where: { userId },
      select: {
        id: true,
        name: true,
        isActive: true,
      },
      orderBy: {
        createdAt: 'desc',
      },
    });
  }
}

export const clientService = new ClientService();
