-- CreateEnum
CREATE TYPE "SourceType" AS ENUM ('GITHUB', 'ZIP');

-- AlterTable
ALTER TABLE "projects" DROP COLUMN "repository_url";

-- CreateTable
CREATE TABLE "repositories" (
    "id" UUID NOT NULL,
    "project_id" UUID NOT NULL,
    "type" "SourceType" NOT NULL DEFAULT 'GITHUB',
    "url" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "repositories_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "repositories_project_id_key" ON "repositories"("project_id");

-- AddForeignKey
ALTER TABLE "repositories" ADD CONSTRAINT "repositories_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "projects"("id") ON DELETE CASCADE ON UPDATE CASCADE;
