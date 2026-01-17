/*
  Warnings:

  - You are about to drop the column `clientSecret` on the `OAuthClient` table. All the data in the column will be lost.
  - You are about to alter the column `domain` on the `OAuthClient` table. The data in that column could be lost. The data in that column will be cast from `Text` to `VarChar(255)`.
  - You are about to alter the column `clientId` on the `OAuthClient` table. The data in that column could be lost. The data in that column will be cast from `Text` to `VarChar(128)`.
  - A unique constraint covering the columns `[clientId]` on the table `OAuthClient` will be added. If there are existing duplicate values, this will fail.

*/
-- CreateEnum
CREATE TYPE "OAuthClientType" AS ENUM ('PUBLIC', 'CONFIDENTIAL');

-- AlterTable
ALTER TABLE "OAuthClient" DROP COLUMN "clientSecret",
ADD COLUMN     "clientSecretHash" VARCHAR(255),
ADD COLUMN     "clientType" "OAuthClientType" NOT NULL DEFAULT 'CONFIDENTIAL',
ADD COLUMN     "enforcePKCE" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "isActive" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "revokedAt" TIMESTAMP(3),
ALTER COLUMN "domain" SET DATA TYPE VARCHAR(255),
ALTER COLUMN "clientId" SET DATA TYPE VARCHAR(128);

-- CreateIndex
CREATE UNIQUE INDEX "OAuthClient_clientId_key" ON "OAuthClient"("clientId");

-- CreateIndex
CREATE INDEX "OAuthClient_clientId_idx" ON "OAuthClient"("clientId");

-- CreateIndex
CREATE INDEX "OAuthClient_domain_idx" ON "OAuthClient"("domain");
