-- CreateEnum
CREATE TYPE "ScanStatus" AS ENUM ('QUEUED', 'INGESTING', 'ANALYZING', 'EXTRACTING', 'SBOM_GENERATING', 'VULNERABILITY_ANALYSIS', 'MATCHING', 'COMPLETED', 'FAILED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "Severity" AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNASSIGNED');

-- CreateTable
CREATE TABLE "users" (
    "id" UUID NOT NULL,
    "email" TEXT NOT NULL,
    "password_hash" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "projects" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "repository_url" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "projects_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scans" (
    "id" UUID NOT NULL,
    "project_id" UUID NOT NULL,
    "status" "ScanStatus" NOT NULL DEFAULT 'QUEUED',
    "error_message" TEXT,
    "risk_score" INTEGER,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completed_at" TIMESTAMP(3),

    CONSTRAINT "scans_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sboms" (
    "id" UUID NOT NULL,
    "scan_id" UUID NOT NULL,
    "cyclone_dx_content" JSONB NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sboms_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "dependencies" (
    "id" UUID NOT NULL,
    "scan_id" UUID NOT NULL,
    "name" TEXT,
    "version" TEXT,
    "purl" TEXT NOT NULL,
    "is_direct" BOOLEAN,
    "ecosystem" TEXT,

    CONSTRAINT "dependencies_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "vulnerabilities" (
    "id" UUID NOT NULL,
    "cve_id" TEXT NOT NULL,
    "description" TEXT,
    "severity" "Severity" NOT NULL DEFAULT 'UNASSIGNED',
    "cvss_score" DECIMAL(3,1),
    "cvss_version" TEXT,
    "published_at" TIMESTAMP(3),
    "modified_at" TIMESTAMP(3),
    "remediation_guidance" TEXT,

    CONSTRAINT "vulnerabilities_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "vulnerable_software" (
    "id" UUID NOT NULL,
    "vulnerability_id" UUID NOT NULL,
    "vendor" TEXT,
    "product" TEXT,
    "version_start_including" TEXT,
    "version_end_excluding" TEXT,
    "version_end_including" TEXT,

    CONSTRAINT "vulnerable_software_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scan_vulnerability_matches" (
    "id" UUID NOT NULL,
    "dependency_id" UUID NOT NULL,
    "vulnerability_id" UUID NOT NULL,
    "match_type" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scan_vulnerability_matches_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE UNIQUE INDEX "vulnerabilities_cve_id_key" ON "vulnerabilities"("cve_id");

-- CreateIndex
CREATE INDEX "vulnerable_software_vendor_product_idx" ON "vulnerable_software"("vendor", "product");

-- AddForeignKey
ALTER TABLE "projects" ADD CONSTRAINT "projects_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scans" ADD CONSTRAINT "scans_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "projects"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sboms" ADD CONSTRAINT "sboms_scan_id_fkey" FOREIGN KEY ("scan_id") REFERENCES "scans"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "dependencies" ADD CONSTRAINT "dependencies_scan_id_fkey" FOREIGN KEY ("scan_id") REFERENCES "scans"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "vulnerable_software" ADD CONSTRAINT "vulnerable_software_vulnerability_id_fkey" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerabilities"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_vulnerability_matches" ADD CONSTRAINT "scan_vulnerability_matches_dependency_id_fkey" FOREIGN KEY ("dependency_id") REFERENCES "dependencies"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_vulnerability_matches" ADD CONSTRAINT "scan_vulnerability_matches_vulnerability_id_fkey" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerabilities"("id") ON DELETE CASCADE ON UPDATE CASCADE;

