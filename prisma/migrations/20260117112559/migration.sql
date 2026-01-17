/*
  Warnings:

  - You are about to drop the column `clientId` on the `OAuthClient` table. All the data in the column will be lost.
  - You are about to drop the column `name` on the `OAuthClient` table. All the data in the column will be lost.

*/
-- DropIndex
DROP INDEX "OAuthClient_clientId_idx";

-- DropIndex
DROP INDEX "OAuthClient_clientId_key";

-- AlterTable
ALTER TABLE "OAuthClient" DROP COLUMN "clientId",
DROP COLUMN "name";
