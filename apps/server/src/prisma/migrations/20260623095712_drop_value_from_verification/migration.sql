/*
  Warnings:

  - You are about to drop the column `value` on the `Verification` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "Verification" DROP COLUMN "value";

-- CreateIndex
CREATE INDEX "Verification_identifier_type_idx" ON "Verification"("identifier", "type");
