-- Q1: Daily trend of newly published CVEs
SELECT
  published_date,
  new_cve_count
FROM agg_daily_new_cves
ORDER BY published_date;

-- Q2: CVSS severity distribution
SELECT
  cvss_severity,
  cve_count
FROM agg_cvss_severity_distribution
ORDER BY cve_count DESC;

-- Q3: KEV hit rate by CVSS severity
SELECT
  cvss_severity,
  total_cves,
  kev_cves,
  kev_hit_rate
FROM agg_kev_hit_rate_by_cvss_severity
ORDER BY kev_hit_rate DESC, total_cves DESC;

-- Q4: Top vendor/product groups by average EPSS score (minimum sample size)
SELECT
  vendor,
  product,
  total_cves,
  scored_cves,
  high_epss_cves,
  high_epss_rate,
  avg_epss_score
FROM agg_epss_by_vendor_product
WHERE scored_cves >= 5
ORDER BY avg_epss_score DESC
LIMIT 20;

-- Q5: Top CWE + vendor + product groups by CVE count
SELECT
  cwe_id,
  vendor,
  product,
  cve_count,
  kev_cves,
  kev_hit_rate,
  avg_epss_score
FROM agg_cwe_vendor_product
WHERE cwe_id <> ''
ORDER BY cve_count DESC
LIMIT 20;

-- Q6: Priority bucket distribution from the star-schema fact table
SELECT
  priority_bucket,
  COUNT(*) AS cve_count
FROM fact_vulnerability_risk
GROUP BY priority_bucket
ORDER BY cve_count DESC;

-- Q7: Monthly CVE publication trend using the date dimension
SELECT
  d.year,
  d.month,
  COUNT(*) AS published_cves
FROM fact_vulnerability_risk f
JOIN dim_date d
  ON f.published_date_key = d.date_key
GROUP BY d.year, d.month
ORDER BY d.year, d.month;

-- Q8: KEV vs non-KEV average EPSS and CVSS comparison
SELECT
  kev_flag,
  COUNT(*) AS cves,
  AVG(cvss_base_score) AS avg_cvss_base_score,
  AVG(epss_score) AS avg_epss_score
FROM fact_vulnerability_risk
GROUP BY kev_flag
ORDER BY kev_flag DESC;

-- Q9: Top critical-priority CVEs for triage (KEV first, then EPSS/CVSS)
SELECT
  cve_id,
  kev_flag,
  cvss_base_score,
  epss_score,
  priority_bucket,
  cvss_severity,
  vendor,
  product
FROM fact_vulnerability_risk
WHERE priority_bucket = 'critical'
ORDER BY kev_flag DESC, epss_score DESC, cvss_base_score DESC
LIMIT 50;

-- Q10: Vendor exposure profile (minimum 10 CVEs)
SELECT
  vendor,
  COUNT(*) AS total_cves,
  SUM(CASE WHEN kev_flag THEN 1 ELSE 0 END) AS kev_cves,
  ROUND(AVG(COALESCE(cvss_base_score, 0)), 4) AS avg_cvss,
  ROUND(AVG(COALESCE(epss_score, 0)), 6) AS avg_epss,
  ROUND(
    SUM(CASE WHEN priority_bucket IN ('critical', 'high') THEN 1 ELSE 0 END)::DOUBLE
    / NULLIF(COUNT(*), 0),
    4
  ) AS high_or_critical_share
FROM fact_vulnerability_risk
WHERE COALESCE(vendor, '') <> ''
GROUP BY vendor
HAVING COUNT(*) >= 10
ORDER BY high_or_critical_share DESC, total_cves DESC
LIMIT 30;

-- Q11: Product-level KEV concentration (minimum 5 CVEs)
SELECT
  vendor,
  product,
  COUNT(*) AS total_cves,
  SUM(CASE WHEN kev_flag THEN 1 ELSE 0 END) AS kev_cves,
  ROUND(
    SUM(CASE WHEN kev_flag THEN 1 ELSE 0 END)::DOUBLE / NULLIF(COUNT(*), 0),
    4
  ) AS kev_rate
FROM fact_vulnerability_risk
WHERE COALESCE(vendor, '') <> ''
  AND COALESCE(product, '') <> ''
GROUP BY vendor, product
HAVING COUNT(*) >= 5
ORDER BY kev_rate DESC, kev_cves DESC, total_cves DESC
LIMIT 30;

-- Q12: CWE risk profile (minimum 20 CVEs per CWE)
SELECT
  cwe_id,
  COUNT(*) AS total_cves,
  SUM(CASE WHEN kev_flag THEN 1 ELSE 0 END) AS kev_cves,
  ROUND(AVG(COALESCE(epss_score, 0)), 6) AS avg_epss,
  ROUND(AVG(COALESCE(cvss_base_score, 0)), 4) AS avg_cvss,
  ROUND(
    SUM(CASE WHEN kev_flag THEN 1 ELSE 0 END)::DOUBLE / NULLIF(COUNT(*), 0),
    4
  ) AS kev_rate
FROM fact_vulnerability_risk
WHERE COALESCE(cwe_id, '') <> ''
GROUP BY cwe_id
HAVING COUNT(*) >= 20
ORDER BY kev_rate DESC, avg_epss DESC, total_cves DESC
LIMIT 30;

-- Q13: Time-to-update signal (published vs last modified, in days)
SELECT
  AVG(DATE_DIFF('day', CAST(published AS DATE), CAST(last_modified AS DATE))) AS avg_days_to_modify,
  MAX(DATE_DIFF('day', CAST(published AS DATE), CAST(last_modified AS DATE))) AS max_days_to_modify,
  MIN(DATE_DIFF('day', CAST(published AS DATE), CAST(last_modified AS DATE))) AS min_days_to_modify
FROM vulnerability_priority
WHERE published IS NOT NULL
  AND last_modified IS NOT NULL;

-- Q14: Data completeness checks for key analytics fields
SELECT
  COUNT(*) AS total_rows,
  SUM(CASE WHEN cve_id IS NULL OR cve_id = '' THEN 1 ELSE 0 END) AS missing_cve_id,
  SUM(CASE WHEN cvss_base_score IS NULL THEN 1 ELSE 0 END) AS missing_cvss_base_score,
  SUM(CASE WHEN epss_score IS NULL THEN 1 ELSE 0 END) AS missing_epss_score,
  SUM(CASE WHEN cwe_id IS NULL OR cwe_id = '' THEN 1 ELSE 0 END) AS missing_cwe_id,
  SUM(CASE WHEN vendor IS NULL OR vendor = '' THEN 1 ELSE 0 END) AS missing_vendor,
  SUM(CASE WHEN product IS NULL OR product = '' THEN 1 ELSE 0 END) AS missing_product
FROM fact_vulnerability_risk;
