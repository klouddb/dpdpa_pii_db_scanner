package piiscanner

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
)

type htmlFinding struct {
	Table      string
	Column     string
	Label      string
	LabelClass string
	Confidence string
	ConfClass  string
	Detector   string
	Matched    string
	MatchedPct int
	BarClass   string
}

type htmlReportData struct {
	Host            string
	Database        string
	ScanType        string
	TableCount      int
	DataCount       int
	MetaCount       int
	LowDataCount    int
	LowMetaCount    int
	DataRows        []htmlFinding
	MetaRows        []htmlFinding
	LowDataRows     []htmlFinding
	LowMetaRows     []htmlFinding
	HasHighFindings bool
	HasLowFindings  bool
}

func CreateHTMLReport(i *DatabasePIIScanOutput, cnf Config, host string) {
	if !i.HasFindings() {
		return
	}

	f, err := os.Create("kshield_pii_report.html")
	if err != nil {
		fmt.Println("Error creating HTML report:", err)
		return
	}
	defer f.Close()

	data := buildHTMLData(i, cnf, host)

	tmpl, err := template.New("report").Parse(htmlReportTemplate)
	if err != nil {
		fmt.Println("Error parsing HTML template:", err)
		return
	}

	if err := tmpl.Execute(f, data); err != nil {
		fmt.Println("Error writing HTML report:", err)
		return
	}

	absPath, _ := filepath.Abs(f.Name())
	fmt.Println("> HTML report created at: [ " + absPath + " ]")
}

func buildHTMLData(i *DatabasePIIScanOutput, cnf Config, host string) htmlReportData {
	scanType := RunOptionTitleMap[cnf.runOption]
	if cnf.AutoDetect {
		scanType = AutoScanTitle
	}
	if cnf.useSpacy {
		scanType = RunOption_SpacyScan_Title
	}

	data := htmlReportData{
		Host:     host,
		Database: cnf.Database,
		ScanType: scanType,
	}

	tableSet := make(map[string]bool)

	for tablename, columns := range i.Data {
		cleanTable := strings.ReplaceAll(tablename, `"`, "")

		for columnName, piidatas := range columns {
			for _, pii := range piidatas {
				tableSet[tablename] = true

				matched := ""
				pct := 0
				barClass := "pii-match-bar-fill--low"
				if pii.DetectorType == DetectorType_ValueDetector && pii.ScanedValueCount > 0 {
					matched = fmt.Sprintf("%d/%d", pii.MatchedCount, pii.ScanedValueCount)
					pct = int(float64(pii.MatchedCount) / float64(pii.ScanedValueCount) * 100)
					if pct >= 95 {
						barClass = "pii-match-bar-fill--high"
					} else if pct >= 70 {
						barClass = "pii-match-bar-fill--medium"
					}
				}

				confClass := "pii-conf-badge--low"
				switch pii.Confidence {
				case "High":
					confClass = "pii-conf-badge--high"
				case "Medium":
					confClass = "pii-conf-badge--medium"
				}

				finding := htmlFinding{
					Table:      cleanTable,
					Column:     columnName,
					Label:      string(pii.Label),
					LabelClass: getLabelClass(string(pii.Label)),
					Confidence: pii.Confidence,
					ConfClass:  confClass,
					Detector:   pii.DetectorName,
					Matched:    matched,
					MatchedPct: pct,
					BarClass:   barClass,
				}

				if pii.Confidence == "High" {
					if pii.DetectorType == DetectorType_ValueDetector {
						data.DataRows = append(data.DataRows, finding)
					} else {
						data.MetaRows = append(data.MetaRows, finding)
					}
				} else {
					if pii.DetectorType == DetectorType_ValueDetector {
						data.LowDataRows = append(data.LowDataRows, finding)
					} else {
						data.LowMetaRows = append(data.LowMetaRows, finding)
					}
				}
			}
		}
	}

	data.TableCount = len(tableSet)
	data.DataCount = len(data.DataRows)
	data.MetaCount = len(data.MetaRows)
	data.LowDataCount = len(data.LowDataRows)
	data.LowMetaCount = len(data.LowMetaRows)
	data.HasHighFindings = data.DataCount > 0 || data.MetaCount > 0
	data.HasLowFindings = data.LowDataCount > 0 || data.LowMetaCount > 0

	return data
}

func getLabelClass(label string) string {
	l := strings.ToLower(label)
	switch {
	case strings.Contains(l, "email"):
		return "pii-label-chip--email"
	case strings.Contains(l, "phone"):
		return "pii-label-chip--phone"
	case strings.Contains(l, "password"):
		return "pii-label-chip--password"
	case strings.Contains(l, "name"), strings.Contains(l, "username"):
		return "pii-label-chip--user"
	case strings.Contains(l, "address"), strings.Contains(l, "location"):
		return "pii-label-chip--address"
	default:
		return "pii-label-chip--default"
	}
}

const htmlReportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Postgres PII Report — {{.Database}}</title>
<style>
:root {
  --kloud-blue: #55a3d7;
  --kloud-blue-soft: rgba(85,163,215,0.12);
  --kloud-purple-mid: #241a30;
  --kloud-border: #424a5f;
  --bg: #0f0520;
  --surface: #2b2338;
  --surface-2: #241a30;
  --border: #424a5f;
  --text: #efefef;
  --text-bright: #ffffff;
  --muted: #a8b0c4;
  --warning: #d4a84b;
  --danger: #e85d75;
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  font-size: 14px;
  padding: 40px 48px;
  min-height: 100vh;
}

h1 { font-size: 26px; font-weight: 600; color: var(--text-bright); letter-spacing: -0.02em; margin-bottom: 6px; }
h2 { font-size: 15px; font-weight: 600; color: var(--text-bright); margin-bottom: 2px; }
.subtitle { color: var(--muted); margin-bottom: 24px; font-size: 13px; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }

.callout {
  display: flex; align-items: center; gap: 10px;
  padding: 12px 16px; border-radius: 8px;
  border-left: 4px solid var(--kloud-blue);
  background: var(--kloud-blue-soft);
  color: var(--muted); font-size: 13px;
  margin-bottom: 24px;
}
.pii-db-badge {
  color: var(--kloud-blue); background: var(--kloud-blue-soft);
  padding: 2px 8px; border-radius: 6px; font-size: 12px;
  font-family: ui-monospace, Consolas, monospace; font-weight: 600;
}

.stats {
  display: grid;
  grid-template-columns: repeat(5, minmax(0,1fr));
  gap: 14px;
  margin-bottom: 24px;
}
@media (max-width: 1100px) { .stats { grid-template-columns: repeat(3, minmax(0,1fr)); } }
@media (max-width: 700px)  { .stats { grid-template-columns: repeat(2, minmax(0,1fr)); } }

.stat-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 20px 22px;
  border-top: 3px solid var(--kloud-purple-mid);
}
.pii-stat--data     { border-top-color: var(--danger); }
.pii-stat--meta     { border-top-color: var(--kloud-blue); }
.pii-stat--low-data { border-top-color: var(--warning); }
.pii-stat--low-meta { border-top-color: #b07dda; }
.stat-label { color: var(--muted); font-size: 13px; font-weight: 500; margin-bottom: 8px; }
.stat-value { font-size: 28px; font-weight: 600; color: var(--text-bright); }

/* Tabs */
.pii-tabs {
  display: flex; gap: 4px;
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 4px;
  margin-bottom: 20px;
  width: fit-content;
}
.pii-tab {
  padding: 8px 20px; border-radius: 7px;
  cursor: pointer; font-size: 13px; font-weight: 500;
  border: none; background: transparent;
  color: var(--muted); transition: all 0.2s;
}
.pii-tab:hover:not(.active) { color: var(--text); }
.pii-tab.active {
  background: var(--surface);
  color: var(--text-bright);
  border: 1px solid var(--border);
  box-shadow: 0 1px 4px rgba(0,0,0,0.3);
}
.pii-tab-panel { display: none; }
.pii-tab-panel.active { display: block; }

.report-block {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  overflow: hidden;
  margin-bottom: 16px;
}
.report-block-header {
  padding: 16px 20px;
  border-bottom: 1px solid var(--border);
  background: var(--surface-2);
  display: flex; align-items: flex-start;
  justify-content: space-between; gap: 16px;
}
.report-block-header p { font-size: 12px; color: var(--muted); margin-top: 3px; }
.report-block-body { padding: 14px; }

.pii-section-badge {
  flex-shrink: 0; padding: 4px 10px; border-radius: 999px;
  font-size: 10px; font-weight: 700; letter-spacing: 0.06em;
}
.pii-section-badge--data { background: rgba(232,93,117,0.12); border: 1px solid rgba(232,93,117,0.35); color: #f0a8b4; }
.pii-section-badge--meta { background: rgba(91,155,213,0.12); border: 1px solid rgba(91,155,213,0.35); color: #55a3d7; }
.pii-section-badge--low  { background: rgba(212,168,75,0.15); border: 1px solid rgba(212,168,75,0.45); color: #e8c878; }

.pii-table-wrap {
  overflow-x: auto; border: 1px solid var(--border);
  border-radius: 10px; background: rgba(0,0,0,0.18);
}
.pii-report-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.pii-report-table thead th {
  position: sticky; top: 0; z-index: 1;
  padding: 8px 10px; text-align: left;
  font-size: 10px; font-weight: 600; letter-spacing: 0.04em;
  color: var(--muted); background: var(--surface-2);
  border-bottom: 1px solid var(--border); white-space: nowrap;
}
.pii-report-table tbody td {
  padding: 7px 10px;
  border-bottom: 1px solid rgba(255,255,255,0.06);
  vertical-align: middle; line-height: 1.3;
}
.pii-report-table tbody tr:last-child td { border-bottom: none; }
.pii-report-table tbody tr:hover td { background: rgba(255,255,255,0.03); }

.pii-col-table    { width: 20%; min-width: 110px; }
.pii-col-column   { width: 14%; min-width: 72px; }
.pii-col-label    { width: 12%; min-width: 72px; }
.pii-col-conf     { width: 10%; min-width: 72px; }
.pii-col-detector { width: 10%; min-width: 64px; }
.pii-col-matched  { width: 20%; min-width: 100px; }

.pii-fq-name, .pii-col-name {
  display: inline-block; max-width: 100%;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 11px; color: var(--text-bright);
  background: rgba(255,255,255,0.05); padding: 2px 6px;
  border-radius: 4px; border: 1px solid rgba(255,255,255,0.08);
}

.pii-label-chip {
  display: inline-flex; align-items: center; padding: 2px 7px;
  border-radius: 4px; font-size: 10px; font-weight: 600;
  letter-spacing: 0.02em; border: 1px solid transparent; white-space: nowrap;
}
.pii-label-chip--email    { background: rgba(232,93,117,0.14); border-color: rgba(232,93,117,0.35); color: #f0a8b4; }
.pii-label-chip--phone    { background: rgba(91,155,213,0.14);  border-color: rgba(91,155,213,0.35);  color: #9ecbf0; }
.pii-label-chip--password { background: rgba(212,168,75,0.14);  border-color: rgba(212,168,75,0.35);  color: #e8c878; }
.pii-label-chip--user     { background: rgba(136,191,87,0.14);  border-color: rgba(136,191,87,0.35);  color: #b8e08a; }
.pii-label-chip--address  { background: rgba(180,130,220,0.14); border-color: rgba(180,130,220,0.35); color: #d4b0f0; }
.pii-label-chip--default  { background: rgba(255,255,255,0.06); border-color: rgba(255,255,255,0.12); color: var(--text); }

.pii-conf-badge {
  display: inline-flex; align-items: center; gap: 4px;
  padding: 2px 7px; border-radius: 999px;
  font-size: 10px; font-weight: 700; letter-spacing: 0.02em; white-space: nowrap;
}
.pii-conf-badge::before { content:''; width:6px; height:6px; border-radius:50%; flex-shrink:0; }
.pii-conf-badge--high   { background: rgba(232,93,117,0.12); color: #f0a8b4; }
.pii-conf-badge--high::before   { background: var(--danger); }
.pii-conf-badge--medium { background: rgba(212,168,75,0.12);  color: #e8c878; }
.pii-conf-badge--medium::before { background: var(--warning); }
.pii-conf-badge--low    { background: rgba(255,255,255,0.06); color: var(--muted); }
.pii-conf-badge--low::before    { background: var(--muted); }

.pii-detector-tag {
  display: inline-block; padding: 2px 6px; border-radius: 4px;
  font-size: 10px; font-family: ui-monospace, Consolas, monospace;
  background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); color: var(--muted);
}

.pii-match-cell { display: flex; flex-direction: column; gap: 3px; min-width: 72px; }
.pii-match-ratio {
  font-family: ui-monospace, Consolas, monospace;
  font-size: 11px; font-weight: 600; color: var(--text-bright);
}
.pii-match-bar {
  display: block; height: 4px; border-radius: 999px;
  background: rgba(255,255,255,0.08); overflow: hidden;
}
.pii-match-bar-fill        { display: block; height: 100%; border-radius: 999px; }
.pii-match-bar-fill--high   { background: var(--danger); }
.pii-match-bar-fill--medium { background: var(--warning); }
.pii-match-bar-fill--low    { background: var(--muted); }

.pii-empty-state {
  text-align: center; padding: 36px 24px;
  border: 1px dashed rgba(255,255,255,0.12);
  border-radius: 10px; background: rgba(0,0,0,0.12);
}
.pii-empty-icon  { font-size: 28px; color: var(--muted); margin-bottom: 12px; opacity: 0.6; }
.pii-empty-title { font-size: 14px; font-weight: 600; color: var(--text-bright); margin: 0 0 6px; }
.pii-empty-hint  { font-size: 12px; color: var(--muted); margin: 0; line-height: 1.5; }

/* Pagination */
.table-pagination {
  display: flex; flex-wrap: wrap; align-items: center;
  justify-content: space-between; gap: 14px;
  margin-top: 14px; padding: 12px 16px;
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; font-size: 13px;
}
.table-pagination__info { color: var(--muted); font-size: 13px; }
.table-pagination__info strong { color: var(--text-bright); font-weight: 600; }
.table-pagination__controls { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.table-pagination__sizes { display: flex; align-items: center; gap: 6px; }
.table-pagination__size {
  padding: 5px 12px; border-radius: 20px;
  border: 1px solid var(--border); background: var(--surface-2);
  color: var(--muted); cursor: pointer; font-size: 12px; transition: all 0.15s;
}
.table-pagination__size:hover { border-color: var(--kloud-blue); color: var(--kloud-blue); }
.table-pagination__size.active {
  border-color: var(--kloud-blue);
  color: var(--kloud-blue); background: var(--kloud-blue-soft); font-weight: 600;
}
.table-pagination__pages { display: flex; align-items: center; gap: 4px; }
.table-pagination__btn {
  min-width: 34px; padding: 5px 10px; border-radius: 6px;
  border: 1px solid var(--border); background: var(--surface-2);
  color: var(--text); cursor: pointer; font-size: 12px;
  transition: all 0.15s; text-align: center;
}
.table-pagination__btn:hover:not(:disabled) { border-color: var(--kloud-blue); color: var(--kloud-blue); }
.table-pagination__btn.active {
  border-color: var(--kloud-blue);
  background: var(--kloud-blue-soft); color: var(--kloud-blue); font-weight: 600;
}
.table-pagination__btn:disabled { opacity: 0.35; cursor: default; }
</style>
</head>
<body>

<h1>Postgres PII Report</h1>
<p class="subtitle">PII results · Scans run via <code>[piiscanner]</code> · <code>dpdpascanner</code></p>

<div class="callout">
  <span>{{.Host}}:5432 &middot; database <span class="pii-db-badge">{{.Database}}</span> &middot; {{.ScanType}}</span>
</div>

<div class="stats">
  <div class="stat-card">
    <div class="stat-label">Tables</div>
    <div class="stat-value">{{.TableCount}}</div>
  </div>
  <div class="stat-card pii-stat--data">
    <div class="stat-label">Data Findings</div>
    <div class="stat-value">{{.DataCount}}</div>
  </div>
  <div class="stat-card pii-stat--meta">
    <div class="stat-label">Meta Findings</div>
    <div class="stat-value">{{.MetaCount}}</div>
  </div>
  <div class="stat-card pii-stat--low-data">
    <div class="stat-label">Low / Medium confidence · Data</div>
    <div class="stat-value">{{.LowDataCount}}</div>
  </div>
  <div class="stat-card pii-stat--low-meta">
    <div class="stat-label">Low / Medium confidence · Meta</div>
    <div class="stat-value">{{.LowMetaCount}}</div>
  </div>
</div>

<div class="pii-tabs">
  <button class="pii-tab active" onclick="switchTab('high', this)">High Confidence</button>
  <button class="pii-tab" onclick="switchTab('low', this)">Low / Medium Confidence</button>
</div>

<!-- HIGH CONFIDENCE PANEL -->
<div id="panel-high" class="pii-tab-panel active">

  {{if .DataRows}}
  <article class="report-block">
    <div class="report-block-header">
      <div>
        <h2>Data Scan Report</h2>
        <p>High-confidence PII detected in column values</p>
      </div>
      <span class="pii-section-badge pii-section-badge--data">Value Scan</span>
    </div>
    <div class="report-block-body">
      <div class="pii-table-wrap">
        <table class="pii-report-table">
          <thead>
            <tr>
              <th class="pii-col-table">Table</th>
              <th class="pii-col-column">Column</th>
              <th class="pii-col-label">Label</th>
              <th class="pii-col-conf">Confidence</th>
              <th class="pii-col-detector">Detector</th>
              <th class="pii-col-matched">Matched</th>
            </tr>
          </thead>
          <tbody id="tbody-data">
          {{range .DataRows}}
          <tr>
            <td class="pii-col-table"><code class="pii-fq-name" title="{{.Table}}">{{.Table}}</code></td>
            <td class="pii-col-column"><code class="pii-col-name">{{.Column}}</code></td>
            <td class="pii-col-label"><span class="pii-label-chip {{.LabelClass}}">{{.Label}}</span></td>
            <td class="pii-col-conf"><span class="pii-conf-badge pii-conf-badge--high">High</span></td>
            <td class="pii-col-detector"><span class="pii-detector-tag">{{.Detector}}</span></td>
            <td class="pii-col-matched">
              <div class="pii-match-cell">
                <span class="pii-match-ratio">{{.Matched}}</span>
                <span class="pii-match-bar">
                  <span class="pii-match-bar-fill {{.BarClass}}" style="width:{{.MatchedPct}}%"></span>
                </span>
              </div>
            </td>
          </tr>
          {{end}}
          </tbody>
        </table>
      </div>
      <div id="pg-data" class="table-pagination"></div>
    </div>
  </article>
  {{end}}

  {{if .MetaRows}}
  <article class="report-block">
    <div class="report-block-header">
      <div>
        <h2>Meta Scan Report</h2>
        <p>PII inferred from column names (metascan / deepscan)</p>
      </div>
      <span class="pii-section-badge pii-section-badge--meta">Meta Scan</span>
    </div>
    <div class="report-block-body">
      <div class="pii-table-wrap">
        <table class="pii-report-table">
          <thead>
            <tr>
              <th class="pii-col-table">Table</th>
              <th class="pii-col-column">Column</th>
              <th class="pii-col-label">Label</th>
              <th class="pii-col-conf">Confidence</th>
            </tr>
          </thead>
          <tbody id="tbody-meta">
          {{range .MetaRows}}
          <tr>
            <td class="pii-col-table"><code class="pii-fq-name" title="{{.Table}}">{{.Table}}</code></td>
            <td class="pii-col-column"><code class="pii-col-name">{{.Column}}</code></td>
            <td class="pii-col-label"><span class="pii-label-chip {{.LabelClass}}">{{.Label}}</span></td>
            <td class="pii-col-conf"><span class="pii-conf-badge pii-conf-badge--high">High</span></td>
          </tr>
          {{end}}
          </tbody>
        </table>
      </div>
      <div id="pg-meta" class="table-pagination"></div>
    </div>
  </article>
  {{end}}

  {{if not .HasHighFindings}}
  <div class="pii-empty-state">
    <div class="pii-empty-icon">&#9671;</div>
    <p class="pii-empty-title">No high-confidence PII found</p>
    <p class="pii-empty-hint">Check the Low / Medium Confidence tab or log files for additional findings.</p>
  </div>
  {{end}}

</div>

<!-- LOW / MEDIUM CONFIDENCE PANEL -->
<div id="panel-low" class="pii-tab-panel">

  {{if .LowDataRows}}
  <article class="report-block">
    <div class="report-block-header">
      <div>
        <h2>Data Scan Report</h2>
        <p>Low / medium confidence PII detected in column values</p>
      </div>
      <span class="pii-section-badge pii-section-badge--low">Value Scan</span>
    </div>
    <div class="report-block-body">
      <div class="pii-table-wrap">
        <table class="pii-report-table">
          <thead>
            <tr>
              <th class="pii-col-table">Table</th>
              <th class="pii-col-column">Column</th>
              <th class="pii-col-label">Label</th>
              <th class="pii-col-conf">Confidence</th>
              <th class="pii-col-detector">Detector</th>
              <th class="pii-col-matched">Matched</th>
            </tr>
          </thead>
          <tbody id="tbody-low-data">
          {{range .LowDataRows}}
          <tr>
            <td class="pii-col-table"><code class="pii-fq-name" title="{{.Table}}">{{.Table}}</code></td>
            <td class="pii-col-column"><code class="pii-col-name">{{.Column}}</code></td>
            <td class="pii-col-label"><span class="pii-label-chip {{.LabelClass}}">{{.Label}}</span></td>
            <td class="pii-col-conf"><span class="pii-conf-badge {{.ConfClass}}">{{.Confidence}}</span></td>
            <td class="pii-col-detector"><span class="pii-detector-tag">{{.Detector}}</span></td>
            <td class="pii-col-matched">
              <div class="pii-match-cell">
                <span class="pii-match-ratio">{{.Matched}}</span>
                <span class="pii-match-bar">
                  <span class="pii-match-bar-fill {{.BarClass}}" style="width:{{.MatchedPct}}%"></span>
                </span>
              </div>
            </td>
          </tr>
          {{end}}
          </tbody>
        </table>
      </div>
      <div id="pg-low-data" class="table-pagination"></div>
    </div>
  </article>
  {{end}}

  {{if .LowMetaRows}}
  <article class="report-block">
    <div class="report-block-header">
      <div>
        <h2>Meta Scan Report</h2>
        <p>Low / medium confidence PII inferred from column names</p>
      </div>
      <span class="pii-section-badge pii-section-badge--low">Meta Scan</span>
    </div>
    <div class="report-block-body">
      <div class="pii-table-wrap">
        <table class="pii-report-table">
          <thead>
            <tr>
              <th class="pii-col-table">Table</th>
              <th class="pii-col-column">Column</th>
              <th class="pii-col-label">Label</th>
              <th class="pii-col-conf">Confidence</th>
            </tr>
          </thead>
          <tbody id="tbody-low-meta">
          {{range .LowMetaRows}}
          <tr>
            <td class="pii-col-table"><code class="pii-fq-name" title="{{.Table}}">{{.Table}}</code></td>
            <td class="pii-col-column"><code class="pii-col-name">{{.Column}}</code></td>
            <td class="pii-col-label"><span class="pii-label-chip {{.LabelClass}}">{{.Label}}</span></td>
            <td class="pii-col-conf"><span class="pii-conf-badge {{.ConfClass}}">{{.Confidence}}</span></td>
          </tr>
          {{end}}
          </tbody>
        </table>
      </div>
      <div id="pg-low-meta" class="table-pagination"></div>
    </div>
  </article>
  {{end}}

  {{if not .HasLowFindings}}
  <div class="pii-empty-state">
    <div class="pii-empty-icon">&#9671;</div>
    <p class="pii-empty-title">No low or medium confidence findings</p>
    <p class="pii-empty-hint">All detected PII entities are high confidence.</p>
  </div>
  {{end}}

</div>

<script>
(function () {
  function switchTab(name, el) {
    document.querySelectorAll('.pii-tab-panel').forEach(function(p) { p.classList.remove('active'); });
    document.querySelectorAll('.pii-tab').forEach(function(t) { t.classList.remove('active'); });
    document.getElementById('panel-' + name).classList.add('active');
    el.classList.add('active');
  }
  window.switchTab = switchTab;

  var PAGE_SIZES = [15, 25, 50];

  function initPagination(tbodyId, pgId) {
    var tbody = document.getElementById(tbodyId);
    var pgEl  = document.getElementById(pgId);
    if (!tbody || !pgEl) return;

    var allRows  = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
    var total    = allRows.length;
    var pageSize = 15;
    var curPage  = 1;

    function totalPages() { return Math.max(1, Math.ceil(total / pageSize)); }

    function render() {
      var tp    = totalPages();
      var start = (curPage - 1) * pageSize;
      var end   = Math.min(start + pageSize, total);

      allRows.forEach(function(r, i) {
        r.style.display = (i >= start && i < end) ? '' : 'none';
      });

      var fromN = total === 0 ? 0 : start + 1;
      var info  = 'Showing <strong>' + fromN + '&ndash;' + end + '</strong> of ' + total;

      var sizes = PAGE_SIZES.map(function(s) {
        var cls = s === pageSize ? 'table-pagination__size active' : 'table-pagination__size';
        return '<button class="' + cls + '" data-size="' + s + '">' + s + ' / page</button>';
      }).join('');

      var prevDis = curPage === 1  ? ' disabled' : '';
      var nextDis = curPage === tp ? ' disabled' : '';
      var pages = '<button class="table-pagination__btn"' + prevDis + ' data-dir="prev">Prev</button>';

      var rangeStart = Math.max(1, curPage - 2);
      var rangeEnd   = Math.min(tp, curPage + 2);
      if (rangeStart > 1) pages += '<button class="table-pagination__btn" data-page="1">1</button>';
      if (rangeStart > 2) pages += '<span style="color:var(--muted);padding:0 4px">&hellip;</span>';
      for (var p = rangeStart; p <= rangeEnd; p++) {
        var ac = p === curPage ? ' active' : '';
        pages += '<button class="table-pagination__btn' + ac + '" data-page="' + p + '">' + p + '</button>';
      }
      if (rangeEnd < tp - 1) pages += '<span style="color:var(--muted);padding:0 4px">&hellip;</span>';
      if (rangeEnd < tp)     pages += '<button class="table-pagination__btn" data-page="' + tp + '">' + tp + '</button>';
      pages += '<button class="table-pagination__btn"' + nextDis + ' data-dir="next">Next</button>';

      pgEl.innerHTML =
        '<span class="table-pagination__info">' + info + '</span>' +
        '<div class="table-pagination__controls">' +
          '<div class="table-pagination__sizes">' + sizes + '</div>' +
          '<div class="table-pagination__pages">' + pages + '</div>' +
        '</div>';
    }

    pgEl.addEventListener('click', function(e) {
      var btn = e.target.closest('button');
      if (!btn) return;
      if (btn.dataset.size) { pageSize = parseInt(btn.dataset.size, 10); curPage = 1; render(); return; }
      if (btn.dataset.dir === 'prev' && curPage > 1) { curPage--; render(); return; }
      if (btn.dataset.dir === 'next' && curPage < totalPages()) { curPage++; render(); return; }
      if (btn.dataset.page) { curPage = parseInt(btn.dataset.page, 10); render(); return; }
    });

    render();
  }

  initPagination('tbody-data',     'pg-data');
  initPagination('tbody-meta',     'pg-meta');
  initPagination('tbody-low-data', 'pg-low-data');
  initPagination('tbody-low-meta', 'pg-low-meta');
})();
</script>

</body>
</html>`
