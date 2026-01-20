-- CreateEnum
CREATE TYPE "KeyStatus" AS ENUM ('ACTIVE', 'RETIRED', 'REVOKED');

-- CreateEnum
CREATE TYPE "KeyUse" AS ENUM ('SIG', 'ENC');

-- CreateEnum
CREATE TYPE "KeyAlgorithm" AS ENUM ('RS256', 'ES256');

-- CreateTable
CREATE TABLE "SigningKeys" (
    "id" TEXT NOT NULL,
    "kid" TEXT NOT NULL,
    "use" "KeyUse" NOT NULL,
    "algorithm" "KeyAlgorithm" NOT NULL,
    "privateKeyEnc" JSONB NOT NULL,
    "publicKey" JSONB NOT NULL,
    "status" "KeyStatus" NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "rotatedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3),

    CONSTRAINT "SigningKeys_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "SigningKeys_kid_key" ON "SigningKeys"("kid");
