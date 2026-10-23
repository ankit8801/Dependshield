-- AlterTable
ALTER TABLE "vulnerabilities" ADD COLUMN     "cvss_vector" TEXT,
ADD COLUMN     "source" TEXT NOT NULL DEFAULT 'NVD';

-- CreateTable
CREATE TABLE "sync_states" (
    "id" TEXT NOT NULL DEFAULT 'NVD',
    "last_sync_date" TIMESTAMP(3) NOT NULL,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "sync_states_pkey" PRIMARY KEY ("id")
);
