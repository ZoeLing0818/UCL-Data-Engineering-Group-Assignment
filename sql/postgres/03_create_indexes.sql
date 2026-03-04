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

CREATE INDEX IF NOT EXISTS idx_dim_products_vendor_product
    ON mart.dim_products (vendor, product);

CREATE INDEX IF NOT EXISTS idx_bridge_cve_products_cve
    ON mart.bridge_cve_products (cve_id);

CREATE INDEX IF NOT EXISTS idx_bridge_cve_products_product
    ON mart.bridge_cve_products (product_key);

CREATE INDEX IF NOT EXISTS idx_dim_date_full_date
    ON mart.dim_date (full_date);

CREATE INDEX IF NOT EXISTS idx_dim_cwe_name
    ON mart.dim_cwe (cwe_name);

CREATE INDEX IF NOT EXISTS idx_fact_vulnerability_risk_cve
    ON mart.fact_vulnerability_risk (cve_id);

CREATE INDEX IF NOT EXISTS idx_fact_vulnerability_risk_snapshot
    ON mart.fact_vulnerability_risk (snapshot_date_key);

CREATE INDEX IF NOT EXISTS idx_fact_vulnerability_risk_priority
    ON mart.fact_vulnerability_risk (priority_bucket);

CREATE INDEX IF NOT EXISTS idx_fact_vulnerability_risk_cvss
    ON mart.fact_vulnerability_risk (cvss_base_score);

CREATE INDEX IF NOT EXISTS idx_fact_vulnerability_risk_priority_key
    ON mart.fact_vulnerability_risk (priority_key);

CREATE INDEX IF NOT EXISTS idx_fact_vulnerability_risk_severity_key
    ON mart.fact_vulnerability_risk (severity_key);
