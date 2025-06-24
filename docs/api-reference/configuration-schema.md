# Configuration Schema Reference

Complete reference for all Vulfy configuration files and options.

## Scan Configuration (`.vulfy.toml`)

Optional configuration file for customizing scan behavior.

### Schema

```toml
[scan]
# Default ecosystems to scan
ecosystems = ["npm", "pypi", "crates.io", "maven", "go", "rubygems", "vcpkg", "packagist", "nuget"]

# Severity threshold (vulnerabilities below this level are ignored)
min_severity = "low"  # Options: "critical", "high", "medium", "low"

# Skip development dependencies
skip_dev_deps = false

# Custom ignore patterns (glob patterns)
ignore_paths = [
    "node_modules",
    "vendor",
    ".git",
    "target",
    "build"
]

[output]
# Default output format
format = "table"  # Options: "table", "json", "csv", "summary", "sarif"

# Color output
color = "auto"  # Options: "auto", "always", "never"

[api]
# OSV.dev API settings
timeout = 30  # Timeout in seconds
max_concurrent = 10  # Maximum concurrent API requests
retry_attempts = 3  # Number of retry attempts on failure
```

### Field Descriptions

#### `[scan]` Section

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ecosystems` | Array[String] | All supported | List of ecosystems to scan |
| `min_severity` | String | `"low"` | Minimum severity level to report |
| `skip_dev_deps` | Boolean | `false` | Skip development dependencies |
| `ignore_paths` | Array[String] | `[]` | Glob patterns for paths to ignore |

#### `[output]` Section

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `format` | String | `"table"` | Default output format |
| `color` | String | `"auto"` | Color output setting |

#### `[api]` Section

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `timeout` | Integer | `30` | API request timeout in seconds |
| `max_concurrent` | Integer | `10` | Maximum concurrent requests |
| `retry_attempts` | Integer | `3` | Number of retry attempts |

---

## Automation Configuration (`vulfy-automation.toml`)

Complete configuration for automation and monitoring features.

### Schema

```toml
# Repository monitoring configuration
[[repositories]]
name = "project-name"
url = "https://github.com/user/repo.git"
branches = ["main", "develop"]  # Optional: specific branches to monitor
local_path = "/path/to/local/repo"  # Optional: use existing local repo
ecosystems = ["npm", "pypi"]  # Optional: filter ecosystems for this repo

[repositories.credentials]
username = "git"  # Optional: Git username
token = "github_token_here"  # Optional: GitHub/GitLab token
ssh_key_path = "/path/to/ssh/key"  # Optional: SSH key path

# Scheduling configuration
[schedule]
frequency = "daily"  # Options: "hourly", "daily", "weekly", "custom"
time = "02:00"  # Time for daily/weekly scans (24-hour format)
timezone = "UTC"  # Timezone (default: UTC)
# For custom frequency, use cron expression in 'time' field

# Notification configuration
[notifications]
enabled = true

[[notifications.webhooks]]
name = "Discord Security Alerts"
url = "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL"
webhook_type = "discord"  # Options: "discord", "slack", "generic"
enabled = true

[notifications.filters]
min_severity = "medium"  # Minimum severity for notifications
only_new_vulnerabilities = true  # Only notify for new vulnerabilities
repositories = ["repo1", "repo2"]  # Optional: specific repos to notify for

# Security policy configuration
[[policies]]
name = "Critical Authentication Issues"
enabled = true

[policies.conditions]
title_contains = ["authentication", "auth", "login"]  # Keywords in title
title_regex = ["(?i)auth.*bypass"]  # Regex patterns for title
description_contains = ["sql injection"]  # Keywords in description
description_regex = ["(?i)remote.*execution"]  # Regex patterns for description
severity = ["high", "critical"]  # Severity levels
ecosystems = ["npm", "pypi"]  # Target ecosystems
cve_pattern = "CVE-2023-.*"  # CVE ID regex pattern
packages = ["lodash", "express"]  # Specific package names
package_regex = ["^@.*/.+"]  # Package name regex patterns

[policies.actions]
notify = true  # Send notifications for matches
priority = "critical"  # Options: "critical", "high", "medium", "low"
custom_message = "🚨 Critical auth vulnerability!"  # Custom notification message
ignore = false  # Ignore vulnerabilities matching this policy
filter_only = false  # Only show vulnerabilities matching this policy

# Storage configuration
[storage]
database_path = "./vulfy-data.db"  # Optional: SQLite database path
retain_days = 30  # Days to retain scan history
export_format = "json"  # Export format for scan results
export_path = "./vulfy-exports"  # Directory for exported results
```

### Field Descriptions

#### `[[repositories]]` Section (Array)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | String | Yes | Unique name for the repository |
| `url` | String | Yes | Git repository URL |
| `branches` | Array[String] | No | Branches to monitor (default: main branch) |
| `local_path` | String | No | Path to existing local repository |
| `ecosystems` | Array[String] | No | Filter ecosystems for this repository |

#### `[repositories.credentials]` Section

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | String | No | Git username for authentication |
| `token` | String | No | GitHub/GitLab personal access token |
| `ssh_key_path` | String | No | Path to SSH private key |

#### `[schedule]` Section

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `frequency` | String | Yes | Schedule frequency |
| `time` | String | No | Time for scheduled scans |
| `timezone` | String | No | Timezone for scheduling (default: UTC) |

**Frequency Options:**
- `"hourly"` - Every hour
- `"daily"` - Once per day at specified time
- `"weekly"` - Once per week at specified day/time
- `"custom"` - Custom cron expression in `time` field

#### `[notifications]` Section

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | Boolean | `true` | Enable/disable notifications |

#### `[[notifications.webhooks]]` Section (Array)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | String | Yes | Webhook name for identification |
| `url` | String | Yes | Webhook URL |
| `webhook_type` | String | Yes | Webhook type |
| `enabled` | Boolean | Yes | Enable/disable this webhook |

**Webhook Types:**
- `"discord"` - Discord webhook format
- `"slack"` - Slack webhook format  
- `"generic"` - Custom JSON webhook format

#### `[notifications.filters]` Section

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `min_severity` | String | `"low"` | Minimum severity for notifications |
| `only_new_vulnerabilities` | Boolean | `false` | Only notify for new vulnerabilities |
| `repositories` | Array[String] | All | Specific repositories to notify for |

#### `[[policies]]` Section (Array)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | String | Yes | Policy name for identification |
| `enabled` | Boolean | Yes | Enable/disable this policy |

#### `[policies.conditions]` Section

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `title_contains` | Array[String] | `[]` | Keywords that must appear in vulnerability title |
| `title_regex` | Array[String] | `[]` | Regex patterns for vulnerability title |
| `description_contains` | Array[String] | `[]` | Keywords in vulnerability description |
| `description_regex` | Array[String] | `[]` | Regex patterns for vulnerability description |
| `severity` | Array[String] | All | Severity levels to match |
| `ecosystems` | Array[String] | All | Target ecosystems |
| `cve_pattern` | String | None | Regex pattern for CVE IDs |
| `packages` | Array[String] | All | Specific package names |
| `package_regex` | Array[String] | `[]` | Regex patterns for package names |

#### `[policies.actions]` Section

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `notify` | Boolean | `false` | Send notifications for matches |
| `priority` | String | `"medium"` | Notification priority level |
| `custom_message` | String | None | Custom notification message |
| `ignore` | Boolean | `false` | Ignore matching vulnerabilities |
| `filter_only` | Boolean | `false` | Only show matching vulnerabilities |

#### `[storage]` Section

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `database_path` | String | None | SQLite database file path |
| `retain_days` | Integer | `30` | Days to retain scan history |
| `export_format` | String | `"json"` | Format for exported results |
| `export_path` | String | `"./vulfy-exports"` | Directory for exports |

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VULFY_LOG` | Log level (error, warn, info, debug, trace) | `info` |
| `VULFY_CONFIG` | Default automation config path | `vulfy-automation.toml` |
| `VULFY_WORKSPACE` | Default workspace directory | `vulfy-workspace` |
| `VULFY_API_TIMEOUT` | OSV.dev API timeout in seconds | `30` |
| `VULFY_MAX_CONCURRENT` | Maximum concurrent API requests | `10` |

---

## Validation Rules

### Repository Configuration
- `name` must be unique across all repositories
- `url` must be a valid Git repository URL
- `branches` must be valid Git branch names
- `ecosystems` must be from supported list

### Schedule Configuration
- `time` format for daily: `"HH:MM"` (24-hour)
- `time` format for custom: valid cron expression
- `timezone` must be valid timezone identifier

### Webhook Configuration
- `url` must be valid HTTPS URL
- Discord webhooks must match Discord URL pattern
- Slack webhooks must match Slack URL pattern

### Policy Configuration
- `title_regex` and `description_regex` must be valid regex patterns
- `cve_pattern` must be valid regex pattern
- `severity` values must be: `"critical"`, `"high"`, `"medium"`, `"low"`
- `priority` values must be: `"critical"`, `"high"`, `"medium"`, `"low"`

---

## Configuration Examples

### Minimal Configuration

```toml
[[repositories]]
name = "my-app"
url = "https://github.com/user/my-app.git"

[schedule]
frequency = "daily"
time = "02:00"

[notifications]
enabled = false
```

### Production Configuration

```toml
[[repositories]]
name = "frontend"
url = "https://github.com/company/frontend.git"
branches = ["main", "staging"]
ecosystems = ["npm"]

[repositories.credentials]
username = "deploy-bot"
token = "ghp_xxxxxxxxxxxx"

[[repositories]]
name = "backend"
url = "https://github.com/company/backend.git"
branches = ["main"]
ecosystems = ["pypi", "go"]

[repositories.credentials]
username = "deploy-bot"
token = "ghp_xxxxxxxxxxxx"

[schedule]
frequency = "daily"
time = "06:00"
timezone = "America/New_York"

[notifications]
enabled = true

[[notifications.webhooks]]
name = "Security Team Discord"
url = "https://discord.com/api/webhooks/xxx/yyy"
webhook_type = "discord"
enabled = true

[[notifications.webhooks]]
name = "Dev Team Slack"
url = "https://hooks.slack.com/services/xxx/yyy/zzz"
webhook_type = "slack"
enabled = true

[notifications.filters]
min_severity = "medium"
only_new_vulnerabilities = true

[[policies]]
name = "Critical Production Issues"
enabled = true

[policies.conditions]
severity = ["critical", "high"]
ecosystems = ["npm", "pypi"]

[policies.actions]
notify = true
priority = "critical"
custom_message = "🚨 Critical vulnerability in production dependencies!"

[[policies]]
name = "Authentication Vulnerabilities"
enabled = true

[policies.conditions]
title_contains = ["auth", "authentication", "login", "session"]
severity = ["high", "critical"]

[policies.actions]
notify = true
priority = "critical"
custom_message = "🔐 Authentication vulnerability detected!"

[storage]
database_path = "./security-data.db"
retain_days = 90
export_format = "json"
export_path = "./security-reports"
```

---

**Next**: [JSON Output Schema](json-output-schema.md) - Structure of JSON scan results 