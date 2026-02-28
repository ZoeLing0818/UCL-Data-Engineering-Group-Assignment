CREATE INDEX IF NOT EXISTS idx_nvd_published
    ON staging.nvd_vulnerabilities (published);

CREATE INDEX IF NOT EXISTS idx_nvd_cvss_score
    ON staging.nvd_vulnerabilities (cvss_base_score);

CREATE INDEX IF NOT EXISTS idx_mart_published
    ON mart.vulnerability_priority (published);

CREATE INDEX IF NOT EXISTS idx_mart_cvss_score
    ON mart.vulnerability_priority (cvss_base_score);

CREATE INDEX IF NOT EXISTS idx_mart_epss_score
    ON mart.vulnerability_priority (epss_score);

CREATE INDEX IF NOT EXISTS idx_mart_priority_bucket
    ON mart.vulnerability_priority (priority_bucket);

CREATE INDEX IF NOT EXISTS idx_mart_in_kev
    ON mart.vulnerability_priority (in_kev);

CREATE INDEX IF NOT EXISTS idx_mart_kev_priority
    ON mart.vulnerability_priority (in_kev, priority_bucket);
