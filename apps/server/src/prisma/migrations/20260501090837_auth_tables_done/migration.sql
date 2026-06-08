-- AlterTable
ALTER TABLE "Account" ALTER COLUMN "password" DROP NOT NULL;

-- AlterTable
ALTER TABLE "Session" ADD COLUMN     "device" TEXT,
ADD COLUMN     "location" TEXT;
