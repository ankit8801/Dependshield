-- AlterTable
ALTER TABLE "scan_vulnerability_matches" ADD COLUMN     "context_weight" DOUBLE PRECISION,
ADD COLUMN     "risk_score" DOUBLE PRECISION,
ADD COLUMN     "severity_weight" DOUBLE PRECISION;

-- AlterTable
ALTER TABLE "scans" ALTER COLUMN "risk_score" SET DATA TYPE DOUBLE PRECISION;
