import crypto from 'crypto';
import { CRYPTO_ALGORITHMS, type CryptoAlgorithm } from './constant.js';

export const randomToken = (bytes = 32): string => crypto.randomBytes(bytes).toString('base64url');

export const sha256 = (value: string): string =>
  crypto.createHash(CRYPTO_ALGORITHMS.sha256).update(value).digest('hex');

export const hmac = (value: string, secret: string): string =>
  crypto.createHmac(CRYPTO_ALGORITHMS.sha256, secret).update(value).digest('hex');

export class AppCrypto {
  static randomToken = (bytes = 32, encoding: BufferEncoding = 'base64url'): string =>
    crypto.randomBytes(bytes).toString(encoding);

  static hash = (
    value: crypto.BinaryLike,
    algorithm: CryptoAlgorithm = CRYPTO_ALGORITHMS.sha256,
    output: crypto.BinaryToTextEncoding = 'hex',
  ): string => {
    return crypto.createHash(algorithm).update(value).digest(output);
  };

  static hmac = (
    value: crypto.BinaryLike,
    key: crypto.BinaryLike,
    algorithm: CryptoAlgorithm,
    output: crypto.BinaryToTextEncoding = 'hex',
  ): string => {
    return crypto.createHmac(algorithm, key).update(value).digest(output);
  };

  static timingSafeCompare = (
    a: crypto.BinaryLike,
    b: crypto.BinaryLike,
    encoding: BufferEncoding = 'hex',
  ): boolean => {
    const bufA = Buffer.isBuffer(a) ? a : Buffer.from(a as any, encoding);
    const bufB = Buffer.isBuffer(b) ? b : Buffer.from(b as any, encoding);

    if (bufA.length !== bufB.length) return false;

    return crypto.timingSafeEqual(bufA, bufB);
  };

  static verifyPKCE(input: {
    codeVerifier: string;
    codeChallenge: string;
    algorithm?: CryptoAlgorithm;
  }): boolean {
    const { codeVerifier, codeChallenge, algorithm = CRYPTO_ALGORITHMS.sha256 } = input;

    if (!codeVerifier || !codeChallenge) {
      return false;
    }

    const derived = this.hash(codeVerifier, algorithm, 'base64url');
    return this.timingSafeCompare(derived, codeChallenge, 'utf8');
  }
}
