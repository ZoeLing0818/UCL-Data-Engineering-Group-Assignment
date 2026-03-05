const CSV_BASE = "../data/curated/transformation_summaries";
const API_BASE = new URLSearchParams(window.location.search).get("api_base") || "";
const COLORS = {
  green: "#1f6b52",
  moss: "#507f62",
  amber: "#b56224",
  cream: "#f3efe5",
  slate: "#39463f",
  red: "#a6403b",
};

const CSV_FILE_MAP = {
  daily: "fact_daily_new_cves_latest.csv",
  cvss: "agg_cvss_severity_distribution_latest.csv",
  kev: "agg_kev_hit_rate_by_cvss_severity_latest.csv",
  epss: "agg_epss_high_risk_by_vendor_product_latest.csv",
  cwe: "agg_cwe_vendor_product_latest.csv",
};

const API_PATH_MAP = {
  daily: "/api/agg/daily-new-cves",
  cvss: "/api/agg/cvss-severity-distribution",
  kev: "/api/agg/kev-hit-rate",
  epss: "/api/agg/epss-vendor-product",
  cwe: "/api/agg/cwe-vendor-product",
};

async function fetchCsvRows(fileName) {
  const response = await fetch(`${CSV_BASE}/${fileName}`);
  if (!response.ok) {
    throw new Error(`Failed to load ${fileName}: ${response.status}`);
  }
  const text = await response.text();
  const [headerLine, ...lines] = text.trim().split(/\r?\n/);
  const headers = splitCsvLine(headerLine);
  return lines
    .filter((line) => line.trim().length > 0)
    .map((line) => {
      const values = splitCsvLine(line);
      return Object.fromEntries(headers.map((header, index) => [header, values[index] ?? ""]));
    });
}

async function fetchApiRows(path) {
  const base = API_BASE.replace(/\/$/, "");
  const response = await fetch(`${base}${path}`);
  if (!response.ok) {
    throw new Error(`Failed to load API ${path}: ${response.status}`);
  }
  return response.json();
}

async function fetchRows(key) {
  if (API_BASE) {
    return fetchApiRows(API_PATH_MAP[key]);
  }
  return fetchCsvRows(CSV_FILE_MAP[key]);
}

function splitCsvLine(line) {
  const values = [];
  let current = "";
  let inQuotes = false;

  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (char === '"') {
      if (inQuotes && line[index + 1] === '"') {
        current += '"';
        index += 1;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === "," && !inQuotes) {
      values.push(current);
      current = "";
    } else {
      current += char;
    }
  }

  values.push(current);
  return values;
}

function toNumber(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function formatPercent(value) {
  return `${(value * 100).toFixed(1)}%`;
}

function normalizeLabel(value, fallback = "unknown") {
  const text = String(value ?? "").trim().toLowerCase();
  if (!text) {
    return fallback;
  }
  return text;
}

function parseDateValue(value) {
  if (!value) {
    return null;
  }
  const date = new Date(`${value}T00:00:00`);
  return Number.isNaN(date.getTime()) ? null : date;
}

function formatLocalDate(date) {
  if (!date) {
    return "";
  }
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function rollingAverage(values, windowSize) {
  const output = [];
  for (let index = 0; index < values.length; index += 1) {
    const start = Math.max(0, index - windowSize + 1);
    const window = values.slice(start, index + 1);
    const avg = window.reduce((sum, value) => sum + value, 0) / window.length;
    output.push(avg);
  }
  return output;
}

function filterDailyByRange(rows, startDate, endDate) {
  return rows.filter((row) => {
    const rowDate = parseDateValue(row.published_date);
    if (!rowDate) {
      return false;
    }
    if (startDate && rowDate < startDate) {
      return false;
    }
    if (endDate && rowDate > endDate) {
      return false;
    }
    return true;
  });
}

function buildHeroStats(dailyRows, kevRows, epssRows, minScoredCves) {
  const totalNewCves = dailyRows.reduce((sum, row) => sum + toNumber(row.new_cve_count), 0);
  const totalCves = kevRows.reduce((sum, row) => sum + toNumber(row.total_cves), 0);
  const totalKev = kevRows.reduce((sum, row) => sum + toNumber(row.kev_cves), 0);
  const highRiskGroups = epssRows.filter(
    (row) => toNumber(row.scored_cves) >= minScoredCves && toNumber(row.high_epss_cves) > 0
  ).length;
  const stats = [
    { label: "CVE Rows (Range)", value: totalNewCves.toLocaleString() },
    { label: "KEV Rate", value: formatPercent(totalKev / Math.max(totalCves, 1)) },
    { label: `High EPSS Groups (>=${minScoredCves})`, value: highRiskGroups.toLocaleString() },
  ];

  document.getElementById("hero-stats").innerHTML = stats
    .map(
      (stat) => `
        <article class="stat-card">
          <span class="stat-label">${stat.label}</span>
          <strong class="stat-value">${stat.value}</strong>
        </article>
      `
    )
    .join("");
}

function buildOverviewCards(dailyRows, epssRows, cweRows, minScoredCves) {
  const totalCves = dailyRows.reduce((sum, row) => sum + toNumber(row.new_cve_count), 0);
  const epssFilteredRows = epssRows.filter((row) => toNumber(row.scored_cves) >= minScoredCves);
  const topProductRow = [...epssFilteredRows].sort(
    (left, right) => toNumber(right.total_cves) - toNumber(left.total_cves)
  )[0];
  const topAverageEpssRow = [...epssFilteredRows]
    .filter((row) => toNumber(row.avg_epss_score) > 0)
    .sort((left, right) => toNumber(right.avg_epss_score) - toNumber(left.avg_epss_score))[0];
  const topCweRow = [...cweRows].sort(
    (left, right) => toNumber(right.cve_count) - toNumber(left.cve_count)
  )[0];

  const cards = [
    {
      label: "Total CVEs",
      value: totalCves.toLocaleString(),
      note: "Rows in the current vulnerability mart",
    },
    {
      label: "Highest-Volume Product",
      value: topProductRow
        ? `${topProductRow.vendor || "unknown"} / ${topProductRow.product || "unknown"}`
        : "N/A",
      note: topProductRow
        ? `${toNumber(topProductRow.total_cves).toLocaleString()} CVEs in this group`
        : "No product grouping available after current filter",
    },
    {
      label: "Top Average EPSS",
      value: topAverageEpssRow
        ? `${topAverageEpssRow.vendor || "unknown"} / ${topAverageEpssRow.product || "unknown"}`
        : "N/A",
      note: topAverageEpssRow
        ? `Average EPSS ${toNumber(topAverageEpssRow.avg_epss_score).toFixed(4)}`
        : "No EPSS grouping available after current filter",
    },
    {
      label: "Most Frequent CWE Group",
      value: topCweRow
        ? `${topCweRow.cwe_id || "No CWE"} | ${topCweRow.vendor || "unknown"} / ${topCweRow.product || "unknown"}`
        : "N/A",
      note: topCweRow
        ? `${toNumber(topCweRow.cve_count).toLocaleString()} CVEs in this grouped pattern`
        : "No CWE grouping available",
    },
  ];

  document.getElementById("overview-grid").innerHTML = cards
    .map(
      (card) => `
        <article class="overview-card">
          <span class="overview-label">${card.label}</span>
          <strong class="overview-value">${card.value}</strong>
          <span class="overview-note">${card.note}</span>
        </article>
      `
    )
    .join("");
}

function buildQualityCards(cvssRows, epssRows, cweRows) {
  const totalCvssRows = cvssRows.reduce((sum, row) => sum + toNumber(row.cve_count), 0);
  const unknownSeverityRows = cvssRows
    .filter((row) => normalizeLabel(row.cvss_severity, "unknown") === "unknown")
    .reduce((sum, row) => sum + toNumber(row.cve_count), 0);

  const totalProductLinks = epssRows.reduce((sum, row) => sum + toNumber(row.total_cves), 0);
  const unknownProductLinks = epssRows
    .filter((row) => {
      const vendor = normalizeLabel(row.vendor);
      const product = normalizeLabel(row.product);
      return vendor === "unknown" || product === "unknown";
    })
    .reduce((sum, row) => sum + toNumber(row.total_cves), 0);

  const totalCweLinks = cweRows.reduce((sum, row) => sum + toNumber(row.cve_count), 0);
  const knownCweLinks = cweRows
    .filter((row) => String(row.cwe_id || "").startsWith("CWE-"))
    .reduce((sum, row) => sum + toNumber(row.cve_count), 0);

  const cards = [
    {
      label: "Unknown Severity Rate",
      value: formatPercent(unknownSeverityRows / Math.max(totalCvssRows, 1)),
      note: `${unknownSeverityRows.toLocaleString()} of ${totalCvssRows.toLocaleString()} severity rows`,
    },
    {
      label: "Unknown Vendor/Product Share",
      value: formatPercent(unknownProductLinks / Math.max(totalProductLinks, 1)),
      note: `${unknownProductLinks.toLocaleString()} of ${totalProductLinks.toLocaleString()} aggregated links`,
    },
    {
      label: "CWE Coverage",
      value: formatPercent(knownCweLinks / Math.max(totalCweLinks, 1)),
      note: `${knownCweLinks.toLocaleString()} of ${totalCweLinks.toLocaleString()} grouped links mapped to CWE`,
    },
  ];

  document.getElementById("quality-grid").innerHTML = cards
    .map(
      (card) => `
        <article class="overview-card">
          <span class="overview-label">${card.label}</span>
          <strong class="overview-value">${card.value}</strong>
          <span class="overview-note">${card.note}</span>
        </article>
      `
    )
    .join("");
}

function renderDailyNewCves(rows) {
  const dailyCounts = rows.map((row) => toNumber(row.new_cve_count));
  const movingAvg = rollingAverage(dailyCounts, 7);
  Plotly.newPlot(
    "daily-new-cves",
    [
      {
        x: rows.map((row) => row.published_date),
        y: dailyCounts,
        type: "scatter",
        mode: "lines+markers",
        line: { color: COLORS.green, width: 3 },
        marker: { size: 7, color: COLORS.amber },
        fill: "tozeroy",
        fillcolor: "rgba(31,107,82,0.12)",
      },
      {
        x: rows.map((row) => row.published_date),
        y: movingAvg,
        type: "scatter",
        mode: "lines",
        line: { color: COLORS.slate, width: 3, dash: "dash" },
        name: "7-day MA",
      },
    ],
    {
      ...baseLayout("New CVEs (Daily + 7-day MA)"),
      showlegend: true,
      legend: { orientation: "h", x: 0, y: 1.14 },
    },
    { responsive: true, displayModeBar: false }
  );
}

function renderCvssDistribution(rows) {
  Plotly.newPlot(
    "cvss-distribution",
    [
      {
        x: rows.map((row) => row.cvss_severity || "UNKNOWN"),
        y: rows.map((row) => toNumber(row.cve_count)),
        type: "bar",
        marker: {
          color: [COLORS.red, COLORS.amber, COLORS.green, COLORS.slate, "#79866f", "#b9b39f"],
        },
      },
    ],
    baseLayout("Severity Counts"),
    { responsive: true, displayModeBar: false }
  );
}

function renderKevHitRate(rows) {
  Plotly.newPlot(
    "kev-hit-rate",
    [
      {
        x: rows.map((row) => row.cvss_severity || "UNKNOWN"),
        y: rows.map((row) => toNumber(row.kev_hit_rate) * 100),
        type: "bar",
        marker: { color: COLORS.amber },
        text: rows.map((row) => formatPercent(toNumber(row.kev_hit_rate))),
        textposition: "outside",
        cliponaxis: false,
      },
    ],
    {
      ...baseLayout("KEV Hit Rate"),
      yaxis: { title: "Percent", ticksuffix: "%", gridcolor: "rgba(24,35,29,0.08)" },
    },
    { responsive: true, displayModeBar: false }
  );
}

function renderEpssVendorProduct(rows) {
  const topRows = rows
    .filter((row) => toNumber(row.scored_cves) > 0)
    .filter((row) => toNumber(row.avg_epss_score) > 0)
    .sort((left, right) => toNumber(right.avg_epss_score) - toNumber(left.avg_epss_score))
    .slice(0, 12);
  Plotly.newPlot(
    "epss-vendor-product",
    [
      {
        x: topRows.map((row) => toNumber(row.avg_epss_score)),
        y: topRows.map((row) => `${row.vendor || "unknown"} / ${row.product || "unknown"}`),
        type: "bar",
        orientation: "h",
        marker: {
          color: topRows.map((row) => toNumber(row.high_epss_rate)),
          colorscale: [
            [0, "#d7d0bc"],
            [0.5, "#b56224"],
            [1, "#1f6b52"],
          ],
        },
        customdata: topRows.map((row) => [
          row.high_epss_cves,
          row.total_cves,
          row.scored_cves,
          row.high_epss_rate,
        ]),
        hovertemplate:
          "%{y}<br>Average EPSS: %{x:.4f}<br>High EPSS CVEs: %{customdata[0]}<br>Total CVEs: %{customdata[1]}<br>Scored CVEs: %{customdata[2]}<br>High EPSS rate: %{customdata[3]}<extra></extra>",
      },
    ],
    {
      ...baseLayout("Average EPSS Score"),
      yaxis: { automargin: true },
      xaxis: { title: "Average EPSS Score", gridcolor: "rgba(24,35,29,0.08)" },
      margin: { l: 180, r: 16, t: 32, b: 44 },
    },
    { responsive: true, displayModeBar: false }
  );
}

function renderCweVendorProduct(rows) {
  const filtered = rows
    .filter((row) => row.cwe_id)
    .slice(0, 15);
  Plotly.newPlot(
    "cwe-vendor-product",
    [
      {
        x: filtered.map((row) => toNumber(row.cve_count)),
        y: filtered.map(
          (row) => `${row.cwe_id} | ${row.vendor || "unknown"} / ${row.product || "unknown"}`
        ),
        type: "bar",
        orientation: "h",
        marker: { color: COLORS.slate },
        customdata: filtered.map((row) => [row.kev_hit_rate, row.avg_epss_score]),
        hovertemplate:
          "%{y}<br>CVE count: %{x}<br>KEV hit rate: %{customdata[0]}<br>Average EPSS: %{customdata[1]}<extra></extra>",
      },
    ],
    {
      ...baseLayout("Top CWE/Vendor/Product Groups"),
      yaxis: { automargin: true },
      xaxis: { title: "CVE Count", gridcolor: "rgba(24,35,29,0.08)" },
      margin: { l: 220, r: 16, t: 32, b: 44 },
    },
    { responsive: true, displayModeBar: false }
  );
}

function baseLayout(title) {
  return {
    title: { text: title, font: { family: "Space Grotesk, sans-serif", size: 18 } },
    paper_bgcolor: "transparent",
    plot_bgcolor: "transparent",
    font: { family: "Space Grotesk, sans-serif", color: COLORS.slate },
    margin: { l: 48, r: 16, t: 36, b: 44 },
    xaxis: { gridcolor: "rgba(24,35,29,0.08)" },
    yaxis: { gridcolor: "rgba(24,35,29,0.08)" },
  };
}

function initializeFilters(dailyRows) {
  const startInput = document.getElementById("filter-start-date");
  const endInput = document.getElementById("filter-end-date");
  const resetButton = document.getElementById("filter-reset");

  const sortedDates = dailyRows
    .map((row) => row.published_date)
    .filter((value) => parseDateValue(value))
    .sort();

  if (sortedDates.length > 0) {
    startInput.value = sortedDates[0];
    endInput.value = sortedDates[sortedDates.length - 1];
    startInput.min = sortedDates[0];
    startInput.max = sortedDates[sortedDates.length - 1];
    endInput.min = sortedDates[0];
    endInput.max = sortedDates[sortedDates.length - 1];
  }

  resetButton.addEventListener("click", () => {
    if (sortedDates.length > 0) {
      startInput.value = sortedDates[0];
      endInput.value = sortedDates[sortedDates.length - 1];
    }
    document.getElementById("filter-min-scored").value = "2";
    renderDashboard();
  });

  startInput.addEventListener("change", renderDashboard);
  endInput.addEventListener("change", renderDashboard);
  document.getElementById("filter-min-scored").addEventListener("change", renderDashboard);
}

let dashboardData = null;

function renderDashboard() {
  if (!dashboardData) {
    return;
  }

  const { dailyRows, cvssRows, kevRows, epssRows, cweRows } = dashboardData;
  const startDate = parseDateValue(document.getElementById("filter-start-date").value);
  const endDate = parseDateValue(document.getElementById("filter-end-date").value);
  const minScoredCves = Math.max(1, toNumber(document.getElementById("filter-min-scored").value));

  let effectiveStart = startDate;
  let effectiveEnd = endDate;
  if (effectiveStart && effectiveEnd && effectiveStart > effectiveEnd) {
    const temp = effectiveStart;
    effectiveStart = effectiveEnd;
    effectiveEnd = temp;
  }

  const filteredDaily = filterDailyByRange(dailyRows, effectiveStart, effectiveEnd);
  const epssMinFiltered = epssRows.filter((row) => toNumber(row.scored_cves) >= minScoredCves);

  buildHeroStats(filteredDaily, kevRows, epssRows, minScoredCves);
  buildOverviewCards(filteredDaily, epssRows, cweRows, minScoredCves);
  buildQualityCards(cvssRows, epssRows, cweRows);
  renderDailyNewCves(filteredDaily);
  renderCvssDistribution(cvssRows);
  renderKevHitRate(kevRows);
  renderEpssVendorProduct(epssMinFiltered);
  renderCweVendorProduct(cweRows);

  const summary = document.getElementById("filter-summary");
  const startLabel = effectiveStart ? formatLocalDate(effectiveStart) : "min";
  const endLabel = effectiveEnd ? formatLocalDate(effectiveEnd) : "max";
  summary.textContent = `Date range: ${startLabel} to ${endLabel} | EPSS groups require scored_cves >= ${minScoredCves}`;
}

async function bootstrap() {
  try {
    const [dailyRows, cvssRows, kevRows, epssRows, cweRows] = await Promise.all([
      fetchRows("daily"),
      fetchRows("cvss"),
      fetchRows("kev"),
      fetchRows("epss"),
      fetchRows("cwe"),
    ]);

    dashboardData = { dailyRows, cvssRows, kevRows, epssRows, cweRows };
    initializeFilters(dailyRows);
    renderDashboard();
  } catch (error) {
    document.querySelector(".dashboard-grid").innerHTML = `
      <section class="panel panel-wide">
        <div class="panel-header">
          <h2>Dashboard Error</h2>
          <p>${error.message}</p>
        </div>
      </section>
    `;
  }
}

window.addEventListener("DOMContentLoaded", bootstrap);
