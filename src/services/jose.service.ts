import * as jose from 'jose';
import crypto from 'crypto';
import prisma, { KeyAlgorithm, KeyStatus, KeyUse } from '@/config/database';
import { Prisma } from 'generated/prisma';
import { ENV } from '@/config/env';

type EncryptedPrivateKey = {
  data: string;
  iv: string;
  tag: string;
};

class JoseService {
  private readonly ALG = 'RS256';
  private readonly ENCRYPTION_KEY = Buffer.from(ENV.KEY_ENC_SECRET!, 'hex');

  // --------------- Generate RSA signing keypair ---------------
  private async generateSigningKey() {
    const { privateKey, publicKey } = await jose.generateKeyPair(this.ALG, {
      modulusLength: 2048,
      extractable: true,
    });

    // Export public JWK
    const publicJwk = await jose.exportJWK(publicKey);

    const kid = crypto
      .createHash('sha256')
      .update(JSON.stringify(publicJwk))
      .digest('base64url')
      .slice(0, 32);

    publicJwk.kid = kid;
    publicJwk.use = 'sig';
    publicJwk.alg = this.ALG;

    return {
      id: crypto.randomUUID(),
      kid,
      algorithm: this.ALG,
      privateKey,
      publicJwk,
    };
  }

  // --------------- Encrypt private key (AES-256-GCM) ---------------
  private async encryptPrivateKey(privateKey: CryptoKey): Promise<EncryptedPrivateKey> {
    const pem = await jose.exportPKCS8(privateKey);

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.ENCRYPTION_KEY, iv);

    const encrypted = Buffer.concat([cipher.update(pem, 'utf8'), cipher.final()]);

    return {
      data: encrypted.toString('base64'),
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
    };
  }

  // --------------- Decrypt private key (internal only) ---------------
  private decryptPrivateKey(enc: EncryptedPrivateKey): crypto.KeyObject {
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      this.ENCRYPTION_KEY,
      Buffer.from(enc.iv, 'base64'),
    );

    decipher.setAuthTag(Buffer.from(enc.tag, 'base64'));

    const decrypted = Buffer.concat([decipher.update(Buffer.from(enc.data, 'base64')), decipher.final()]);

    return crypto.createPrivateKey(decrypted.toString('utf8'));
  }

  // ---------------Initialize JWKS (first boot) ---------------
  async initJwks() {
    const keysCount = await prisma.signingKeys.count();
    if (keysCount >= 1) return;

    // start creation
    const key = await this.generateSigningKey();
    const encryptedPrivateKey = await this.encryptPrivateKey(key.privateKey);
    const publicKeyJson = key.publicJwk as Prisma.InputJsonValue;

    // store in DB
    await prisma.signingKeys.create({
      data: {
        id: key.id,
        kid: key.kid,
        use: 'SIG',
        algorithm: KeyAlgorithm.RS256,
        privateKeyEnc: encryptedPrivateKey,
        publicKey: publicKeyJson,
        status: 'ACTIVE',
        createdAt: new Date(),
      },
    });
  }

  // --------------- Get active private signing key ---------------
  private async getActiveSigningKey() {
    const key = await prisma.signingKeys.findFirst({
      where: { status: 'ACTIVE', use: 'SIG' },
    });

    if (!key) {
      throw new Error('No active signing key found');
    }

    const privateKey = this.decryptPrivateKey(key.privateKeyEnc as EncryptedPrivateKey);

    return {
      kid: key.kid,
      privateKey,
    };
  }

  // TODO: Rotate keys in a scheduled manner
  // --------------- Rotate signing keys (safe) ---------------
  async rotateSigningKey() {
    const newKey = await this.generateSigningKey();
    const encryptedPrivateKey = await this.encryptPrivateKey(newKey.privateKey);
    const publicKeyJson = newKey.publicJwk as Prisma.InputJsonValue;

    // retire all old keys
    await prisma.$transaction(async (tx) => {
      await tx.signingKeys.updateMany({
        where: { status: 'ACTIVE', use: 'SIG' },
        data: {
          status: 'RETIRED',
          rotatedAt: new Date(),
        },
      });

      // add the new key as active
      await tx.signingKeys.create({
        data: {
          id: newKey.id,
          kid: newKey.kid,
          use: 'SIG',
          algorithm: KeyAlgorithm.RS256,
          privateKeyEnc: encryptedPrivateKey,
          publicKey: publicKeyJson,
          status: 'ACTIVE',
          createdAt: new Date(),
        },
      });
    });
  }

  // --------------- JWKS for public endpoint ---------------
  async getJwks() {
    const keys = await prisma.signingKeys.findMany({
      where: {
        status: { in: ['ACTIVE', 'RETIRED'] },
        use: 'SIG',
      },
      select: {
        publicKey: true,
      },
    });

    return {
      keys: keys.map((k) => k.publicKey),
    };
  }

  // --------------- Sign JWT (Access / ID token) ---------------
  async signJwt(
    payload: Record<string, any>,
    options: {
      issuer: string;
      audience: string;
      expiresIn: string;
    },
  ) {
    const { privateKey, kid } = await this.getActiveSigningKey();

    return new jose.SignJWT(payload)
      .setProtectedHeader({ alg: this.ALG, kid })
      .setIssuer(options.issuer)
      .setAudience(options.audience)
      .setIssuedAt()
      .setExpirationTime(options.expiresIn)
      .sign(privateKey);
  }
}

export const joseService = new JoseService();
