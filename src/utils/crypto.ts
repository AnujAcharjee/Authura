import crypto from 'crypto';

export const randomToken = (bytes = 32): string => crypto.randomBytes(bytes).toString('base64url');

export const sha256 = (value: string): string => crypto.createHash('sha256').update(value).digest('hex');

export const verifyPKCE = ({
  codeVerifier,
  codeChallenge,
  method,
}: {
  codeVerifier?: string;
  codeChallenge?: string;
  method?: 'S256';
}): boolean => {
  if (!codeVerifier || !codeChallenge || !method) {
    return false;
  }

  const derivedChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

  // CONSTANT-TIME COMPARISON
  const a = Buffer.from(derivedChallenge);
  const b = Buffer.from(codeChallenge);

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return false;
  }

  return true;
};