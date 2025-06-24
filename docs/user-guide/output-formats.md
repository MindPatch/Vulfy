# Output Formats Guide

Vulfy supports multiple output formats to fit different use cases, from human-readable reports to machine-processable data.

## Available Formats

| Format | Use Case | File Extension | Description |
|--------|----------|----------------|-------------|
| `table` | Interactive use | - | Beautiful ASCII tables with colors |
| `json` | Programmatic use | `.json` | Structured data for automation |
| `csv` | Spreadsheet analysis | `.csv` | Comma-separated values |
| `summary` | Quick overview | `.txt` | Statistics only |
| `sarif` | Static analysis tools | `.sarif` | SARIF 2.1.0 standard |

## Table Format (Default)

The table format provides a beautiful, human-readable output with color coding and emojis.

### Usage

```bash
vulfy scan packages
# or explicitly
vulfy scan packages --format table
```

### Example Output

```
🔍 Scanning for package files...
📦 Found 6 package files across 4 ecosystems

🛡️  VULNERABILITY REPORT
┌─────────────────────────────────────────┬──────────────┬──────────┬─────────────────┬──────┐
│ Title                                   │ CVE ID       │ Severity │ Package         │ Year │
├─────────────────────────────────────────┼──────────────┼──────────┼─────────────────┼──────┤
│ Remote Code Execution in lodash        │ CVE-2021-123 │ 🔥 High  │ lodash@4.17.0   │ 2021 │
│ Path Traversal in express              │ CVE-2022-456 │ 🟡 Medium│ express@4.16.0  │ 2022 │
│ SQL Injection in sequelize             │ CVE-2020-789 │ 🔥 High  │ sequelize@5.0.0 │ 2020 │
└─────────────────────────────────────────┴──────────────┴──────────┴─────────────────┴──────┘

📊 SCAN SUMMARY
• Total packages scanned: 42
• Vulnerable packages: 8
• Total vulnerabilities: 12
• 🔥 High severity: 4
• 🟡 Medium severity: 6
• 🟢 Low severity: 2

🏗️ ECOSYSTEM BREAKDOWN
┌─────────────┬──────────┬─────────────┬──────────────────┐
│ Ecosystem   │ Packages │ Vulnerable  │ Vulnerabilities  │
├─────────────┼──────────┼─────────────┼──────────────────┤
│ npm         │ 28       │ 5           │ 8                │
│ PyPI        │ 12       │ 2           │ 3                │
│ Maven       │ 2        │ 1           │ 1                │
└─────────────┴──────────┴─────────────┴──────────────────┘
```

### Features

- **Color Coding**: Severity levels have distinct colors
- **Emoji Icons**: Visual indicators for severity and status
- **Clean Layout**: Well-formatted tables with proper alignment
- **Progress Information**: Scan progress and file discovery updates
- **Ecosystem Breakdown**: Summary by package manager

## JSON Format

Structured JSON output for programmatic processing and automation.

### Usage

```bash
vulfy scan packages --format json --output security-report.json
```

### Schema

```json
{
  "scan_id": "uuid-string",
  "timestamp": "2024-01-15T10:30:00Z",
  "scanned_path": "/path/to/project",
  "summary": {
    "total_packages": 42,
    "vulnerable_packages": 8,
    "total_vulnerabilities": 12,
    "severity_counts": {
      "critical": 0,
      "high": 4,
      "medium": 6,
      "low": 2
    }
  },
  "vulnerabilities": [
    {
      "id": "CVE-2021-123",
      "title": "Remote Code Execution in lodash",
      "severity": "HIGH",
      "package": "lodash",
      "version": "4.17.0",
      "ecosystem": "npm",
      "published": "2021-05-15T00:00:00Z",
      "modified": "2021-05-20T00:00:00Z",
      "aliases": ["GHSA-abc-123"],
      "summary": "A vulnerability in lodash allows remote code execution...",
      "details": "Detailed vulnerability description...",
      "affected_versions": ["<4.17.21"],
      "references": [
        {
          "type": "ADVISORY",
          "url": "https://github.com/advisories/GHSA-abc-123"
        },
        {
          "type": "WEB",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-123"
        }
      ]
    }
  ],
  "ecosystem_summary": {
    "npm": {
      "total_packages": 28,
      "vulnerable_packages": 5,
      "total_vulnerabilities": 8
    },
    "pypi": {
      "total_packages": 12,
      "vulnerable_packages": 2,
      "total_vulnerabilities": 3
    }
  }
}
```

### Use Cases

- **CI/CD Integration**: Parse results in build pipelines
- **Security Dashboards**: Feed data into monitoring systems
- **Automated Reporting**: Generate custom reports
- **Data Analysis**: Process vulnerability trends

## CSV Format

Comma-separated values format for spreadsheet analysis and data processing.

### Usage

```bash
vulfy scan packages --format csv --output vulnerabilities.csv
```

### Schema

```csv
id,title,severity,package,version,ecosystem,published,modified,summary,references
CVE-2021-123,"Remote Code Execution in lodash",HIGH,lodash,4.17.0,npm,2021-05-15T00:00:00Z,2021-05-20T00:00:00Z,"A vulnerability in lodash allows remote code execution...","https://github.com/advisories/GHSA-abc-123;https://nvd.nist.gov/vuln/detail/CVE-2021-123"
CVE-2022-456,"Path Traversal in express",MEDIUM,express,4.16.0,npm,2022-03-10T00:00:00Z,2022-03-15T00:00:00Z,"Path traversal vulnerability in express...","https://github.com/advisories/GHSA-def-456"
```

### Features

- **Excel Compatible**: Opens directly in spreadsheet applications
- **Flat Structure**: Each vulnerability is a single row
- **Reference URLs**: Multiple references separated by semicolons
- **Sortable Data**: Easy to sort and filter by any column

### Use Cases

- **Executive Reports**: Create charts and graphs in Excel
- **Risk Assessment**: Analyze vulnerability patterns
- **Compliance Reporting**: Generate audit-ready reports
- **Data Export**: Transfer data to other security tools

## Summary Format

Condensed output showing only statistics and key metrics.

### Usage

```bash
vulfy scan packages --format summary
```

### Example Output

```
VULFY SCAN SUMMARY
==================

Scan completed: 2024-01-15 10:30:00 UTC
Scanned path: /path/to/project

PACKAGE STATISTICS
• Total packages scanned: 42
• Vulnerable packages: 8 (19%)
• Total vulnerabilities: 12

SEVERITY BREAKDOWN
• 🔥 High severity: 4 vulnerabilities
• 🟡 Medium severity: 6 vulnerabilities  
• 🟢 Low severity: 2 vulnerabilities

ECOSYSTEM BREAKDOWN
• npm: 28 packages (5 vulnerable, 8 vulnerabilities)
• PyPI: 12 packages (2 vulnerable, 3 vulnerabilities)
• Maven: 2 packages (1 vulnerable, 1 vulnerability)

RECOMMENDATIONS
• Review 4 high-severity vulnerabilities immediately
• Consider updating vulnerable packages
• Run scans regularly to catch new vulnerabilities
```

### Use Cases

- **Quick Assessment**: Fast overview of security posture
- **Dashboard Integration**: High-level metrics for monitoring
- **Email Reports**: Concise summaries for stakeholders
- **Status Checks**: Quick validation after updates

## SARIF Format

Static Analysis Results Interchange Format (SARIF) 2.1.0 for integration with static analysis tools.

### Usage

```bash
vulfy scan packages --format sarif --output vulfy.sarif
```

### Schema

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Vulfy",
          "version": "0.1.0",
          "informationUri": "https://github.com/mindPatch/vulfy",
          "rules": [
            {
              "id": "CVE-2021-123",
              "name": "Remote Code Execution in lodash",
              "shortDescription": {
                "text": "Remote Code Execution vulnerability"
              },
              "fullDescription": {
                "text": "A vulnerability in lodash allows remote code execution..."
              },
              "helpUri": "https://nvd.nist.gov/vuln/detail/CVE-2021-123",
              "properties": {
                "security-severity": "7.5",
                "tags": ["security", "vulnerability"]
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "CVE-2021-123",
          "level": "error",
          "message": {
            "text": "Package lodash@4.17.0 has a high severity vulnerability"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "package-lock.json"
                },
                "region": {
                  "startLine": 1
                }
              }
            }
          ],
          "properties": {
            "package_name": "lodash",
            "package_version": "4.17.0",
            "ecosystem": "npm",
            "cve_id": "CVE-2021-123"
          }
        }
      ]
    }
  ]
}
```

### Use Cases

- **GitHub Security Tab**: Upload SARIF files to GitHub
- **IDE Integration**: View vulnerabilities in code editors
- **Security Tools**: Import into other SARIF-compatible tools
- **Compliance**: Meet SARIF reporting requirements

## Format Comparison

| Feature | Table | JSON | CSV | Summary | SARIF |
|---------|-------|------|-----|---------|-------|
| Human Readable | ✅ | ❌ | ⚠️ | ✅ | ❌ |
| Machine Readable | ❌ | ✅ | ✅ | ❌ | ✅ |
| CI/CD Integration | ⚠️ | ✅ | ✅ | ✅ | ✅ |
| Spreadsheet Import | ❌ | ❌ | ✅ | ❌ | ❌ |
| Tool Integration | ❌ | ✅ | ⚠️ | ❌ | ✅ |
| File Size | Small | Large | Medium | Small | Large |
| Color Support | ✅ | ❌ | ❌ | ✅ | ❌ |

## Output Options

### File Output

Save results to files instead of displaying on screen:

```bash
# Save JSON to file
vulfy scan packages --format json --output security-report.json

# Save CSV to file  
vulfy scan packages --format csv --output vulnerabilities.csv

# Save SARIF for GitHub
vulfy scan packages --format sarif --output vulfy.sarif
```

### Stdout vs File

- **Table format**: Always outputs to stdout (terminal)
- **Other formats**: Can output to stdout or file
- **File output**: Recommended for JSON, CSV, and SARIF formats
- **Stdout output**: Useful for piping to other commands

### Combining with Filters

All formats work with filtering options:

```bash
# High-severity vulnerabilities only
vulfy scan packages --format json --high-only --output high-severity.json

# Specific ecosystems
vulfy scan packages --format csv --ecosystems npm,pypi --output web-vulns.csv

# Quiet mode (suppresses progress info)
vulfy scan packages --format json --quiet --output report.json
```

## Best Practices

### Format Selection

1. **Interactive Use**: Use `table` format for manual scanning
2. **Automation**: Use `json` format for CI/CD and scripting
3. **Reporting**: Use `csv` format for spreadsheet analysis
4. **Monitoring**: Use `summary` format for dashboards
5. **Tool Integration**: Use `sarif` format for static analysis tools

### File Management

1. **Naming Convention**: Use descriptive filenames with timestamps
2. **Directory Structure**: Organize reports by project and date
3. **Retention Policy**: Archive old reports to prevent disk bloat
4. **Version Control**: Don't commit scan results to Git

### CI/CD Integration

```bash
# Generate multiple formats in CI
vulfy scan packages --format json --output vulfy-report.json
vulfy scan packages --format sarif --output vulfy.sarif
vulfy scan packages --format summary --output vulfy-summary.txt

# Upload SARIF to GitHub Security tab
gh api repos/:owner/:repo/code-scanning/sarifs \
  --field sarif=@vulfy.sarif
```

---

**Next**: [Configuration Guide](configuration.md) - Detailed configuration options 