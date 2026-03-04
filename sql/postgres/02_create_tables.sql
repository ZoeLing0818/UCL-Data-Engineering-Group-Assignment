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

CREATE TABLE IF NOT EXISTS mart.dim_products (
    product_key VARCHAR PRIMARY KEY,
    cpe_uri VARCHAR NOT NULL,
    cpe_part VARCHAR NULL,
    vendor VARCHAR NULL,
    product VARCHAR NULL,
    product_version VARCHAR NULL,
    target_software VARCHAR NULL,
    target_hardware VARCHAR NULL
);

CREATE TABLE IF NOT EXISTS mart.bridge_cve_products (
    cve_id VARCHAR NOT NULL,
    product_key VARCHAR NOT NULL,
    vendor VARCHAR NULL,
    product VARCHAR NULL,
    is_vulnerable BOOLEAN NOT NULL,
    version_start_including VARCHAR NULL,
    version_start_excluding VARCHAR NULL,
    version_end_including VARCHAR NULL,
    version_end_excluding VARCHAR NULL,
    match_criteria_id VARCHAR NULL,
    node_operator VARCHAR NULL,
    node_negate BOOLEAN NOT NULL,
    PRIMARY KEY (cve_id, product_key, match_criteria_id),
    FOREIGN KEY (cve_id) REFERENCES mart.vulnerability_priority (cve_id),
    FOREIGN KEY (product_key) REFERENCES mart.dim_products (product_key)
);

CREATE TABLE IF NOT EXISTS mart.dim_date (
    date_key INTEGER PRIMARY KEY,
    full_date DATE NOT NULL,
    year INTEGER NOT NULL,
    quarter INTEGER NOT NULL,
    month INTEGER NOT NULL,
    month_name VARCHAR NOT NULL,
    week_of_year INTEGER NOT NULL,
    day_of_month INTEGER NOT NULL,
    day_of_week INTEGER NOT NULL,
    day_name VARCHAR NOT NULL
);

CREATE TABLE IF NOT EXISTS mart.dim_priority (
    priority_key INTEGER PRIMARY KEY,
    priority_bucket VARCHAR NOT NULL UNIQUE,
    priority_rank INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS mart.dim_severity (
    severity_key INTEGER PRIMARY KEY,
    cvss_severity VARCHAR NOT NULL UNIQUE,
    severity_rank INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS mart.dim_cwe (
    cwe_key VARCHAR PRIMARY KEY,
    cwe_name VARCHAR NULL,
    cwe_description TEXT NULL
);

CREATE TABLE IF NOT EXISTS mart.fact_vulnerability_risk (
    fact_id BIGINT PRIMARY KEY,
    cve_id VARCHAR NOT NULL,
    snapshot_date_key INTEGER NOT NULL,
    published_date_key INTEGER NULL,
    last_modified_date_key INTEGER NULL,
    kev_date_added_key INTEGER NULL,
    kev_due_date_key INTEGER NULL,
    cwe_key VARCHAR NULL,
    priority_key INTEGER NOT NULL,
    severity_key INTEGER NOT NULL,
    cwe_id VARCHAR NULL,
    vendor VARCHAR NULL,
    product VARCHAR NULL,
    vuln_status VARCHAR NULL,
    cvss_version VARCHAR NULL,
    cvss_severity VARCHAR NULL,
    priority_bucket VARCHAR NOT NULL,
    kev_ransomware_use VARCHAR NULL,
    cvss_base_score DOUBLE PRECISION NULL,
    epss_score DOUBLE PRECISION NULL,
    epss_percentile DOUBLE PRECISION NULL,
    kev_flag BOOLEAN NOT NULL,
    vulnerable_product_count INTEGER NOT NULL,
    FOREIGN KEY (snapshot_date_key) REFERENCES mart.dim_date (date_key),
    FOREIGN KEY (published_date_key) REFERENCES mart.dim_date (date_key),
    FOREIGN KEY (last_modified_date_key) REFERENCES mart.dim_date (date_key),
    FOREIGN KEY (kev_date_added_key) REFERENCES mart.dim_date (date_key),
    FOREIGN KEY (kev_due_date_key) REFERENCES mart.dim_date (date_key),
    FOREIGN KEY (cwe_key) REFERENCES mart.dim_cwe (cwe_key),
    FOREIGN KEY (priority_key) REFERENCES mart.dim_priority (priority_key),
    FOREIGN KEY (severity_key) REFERENCES mart.dim_severity (severity_key),
    CONSTRAINT chk_fact_cvss_score_range CHECK (
        cvss_base_score IS NULL OR (cvss_base_score >= 0 AND cvss_base_score <= 10)
    ),
    CONSTRAINT chk_fact_epss_score_range CHECK (
        epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)
    ),
    CONSTRAINT chk_fact_epss_percentile_range CHECK (
        epss_percentile IS NULL OR (epss_percentile >= 0 AND epss_percentile <= 1)
    ),
    CONSTRAINT chk_fact_priority_bucket CHECK (
        priority_bucket IN ('low', 'medium', 'high', 'critical')
    )
);
