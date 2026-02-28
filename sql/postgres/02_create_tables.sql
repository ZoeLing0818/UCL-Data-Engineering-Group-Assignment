CREATE TABLE IF NOT EXISTS staging.nvd_vulnerabilities (
    cve_id VARCHAR PRIMARY KEY,
    published TIMESTAMP NULL,
    last_modified TIMESTAMP NULL,
    vuln_status VARCHAR NULL,
    cvss_version VARCHAR NULL,
    cvss_base_score DOUBLE PRECISION NULL,
    cvss_severity VARCHAR NULL,
    cwe_id VARCHAR NULL,
    vendor VARCHAR NULL,
    product VARCHAR NULL
);

CREATE TABLE IF NOT EXISTS staging.cisa_kev (
    cve_id VARCHAR PRIMARY KEY,
    kev_date_added DATE NULL,
    kev_due_date DATE NULL,
    kev_ransomware_use VARCHAR NULL
);

CREATE TABLE IF NOT EXISTS staging.epss_scores (
    cve_id VARCHAR PRIMARY KEY,
    epss_score DOUBLE PRECISION NULL,
    epss_percentile DOUBLE PRECISION NULL
);

CREATE TABLE IF NOT EXISTS mart.vulnerability_priority (
    cve_id VARCHAR PRIMARY KEY,
    published TIMESTAMP NULL,
    last_modified TIMESTAMP NULL,
    vuln_status VARCHAR NULL,
    cvss_version VARCHAR NULL,
    cvss_base_score DOUBLE PRECISION NULL,
    cvss_severity VARCHAR NULL,
    cwe_id VARCHAR NULL,
    vendor VARCHAR NULL,
    product VARCHAR NULL,
    in_kev BOOLEAN NOT NULL,
    kev_date_added DATE NULL,
    kev_due_date DATE NULL,
    kev_ransomware_use VARCHAR NULL,
    epss_score DOUBLE PRECISION NULL,
    epss_percentile DOUBLE PRECISION NULL,
    priority_bucket VARCHAR NOT NULL,
    CONSTRAINT chk_cvss_score_range CHECK (
        cvss_base_score IS NULL OR (cvss_base_score >= 0 AND cvss_base_score <= 10)
    ),
    CONSTRAINT chk_epss_score_range CHECK (
        epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)
    ),
    CONSTRAINT chk_epss_percentile_range CHECK (
        epss_percentile IS NULL OR (epss_percentile >= 0 AND epss_percentile <= 1)
    ),
    CONSTRAINT chk_priority_bucket CHECK (
        priority_bucket IN ('low', 'medium', 'high', 'critical')
    )
);
