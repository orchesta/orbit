-- Rollback initial schema

DROP TABLE IF EXISTS vulnerabilities;
DROP TABLE IF EXISTS dependencies;
DROP TABLE IF EXISTS scan_results;
DROP TABLE IF EXISTS repositories;
DROP EXTENSION IF EXISTS "uuid-ossp";
