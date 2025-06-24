# Automation Overview

Vulfy's automation system provides continuous security monitoring for your Git repositories with intelligent scheduling, notifications, and advanced policy-based filtering.

## What is Automation?

The automation system transforms Vulfy from a one-time scanner into a continuous security monitoring solution that:

- 🔄 **Monitors Git repositories** continuously for new vulnerabilities
- ⏰ **Schedules regular scans** with flexible timing options
- 🔔 **Sends smart notifications** via Discord, Slack, and webhooks
- 📋 **Applies security policies** for intelligent vulnerability filtering
- 🏗️ **Supports multiple ecosystems** per repository
- 🔐 **Handles authentication** for private repositories

## Key Features

### Repository Monitoring
- Monitor multiple Git repositories simultaneously
- Support for public and private repositories
- Branch-specific scanning (main, develop, staging, etc.)
- Automatic repository cloning and updates
- Ecosystem filtering per repository

### Intelligent Scheduling
- **Hourly**: For critical production repositories
- **Daily**: Standard monitoring at specified time
- **Weekly**: For less critical or stable projects
- **Custom Cron**: Full cron expression support for complex schedules

### Smart Notifications
- **Discord Integration**: Rich embed messages with severity colors
- **Slack Integration**: Formatted messages with action buttons
- **Generic Webhooks**: Custom webhook formats for other services
- **Severity Filtering**: Only notify for high/critical vulnerabilities
- **New Vulnerability Detection**: Avoid notification spam

### Advanced Policy Engine
- **Keyword Matching**: Filter by vulnerability titles and descriptions
- **Severity Thresholds**: Set minimum severity levels
- **Package Filtering**: Target specific packages or patterns
- **CVE Pattern Matching**: Regex matching for specific CVE types
- **Ecosystem Targeting**: Per-ecosystem policy rules

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Scheduler     │───▶│  Git Monitor     │───▶│   Scanner       │
│  (Cron Jobs)    │    │ (Clone/Update)   │    │ (Vulnerability  │
└─────────────────┘    └──────────────────┘    │   Detection)    │
                                               └─────────────────┘
                                                        │
┌─────────────────┐    ┌──────────────────┐           │
│  Notifications  │◀───│  Policy Engine   │◀──────────┘
│ (Discord/Slack) │    │   (Filtering)    │
└─────────────────┘    └──────────────────┘
```

## Quick Start

### 1. Initialize Configuration

```bash
# Create basic configuration
vulfy automation init

# Create with example repositories and policies
vulfy automation init --with-examples
```

### 2. Configure Repositories

Edit `vulfy-automation.toml`:

```toml
[[repositories]]
name = "my-web-app"
url = "https://github.com/user/my-web-app.git"
branches = ["main", "develop"]
ecosystems = ["npm", "pypi"]

[repositories.credentials]
username = "git"
token = "your_github_token_here"
```

### 3. Set Up Notifications

```toml
[[notifications.webhooks]]
name = "Security Alerts"
url = "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL"
webhook_type = "discord"
enabled = true

[notifications.filters]
min_severity = "medium"
only_new_vulnerabilities = true
```

### 4. Start Monitoring

```bash
# Start scheduler as daemon
vulfy automation start

# Or run in foreground for debugging
vulfy automation start --foreground
```

## Configuration Structure

### Basic Configuration

```toml
# Repository monitoring
[[repositories]]
name = "project-name"
url = "https://github.com/user/repo.git"
branches = ["main"]
ecosystems = ["npm", "pypi"]

# Scheduling
[schedule]
frequency = "daily"
time = "02:00"
timezone = "UTC"

# Notifications
[notifications]
enabled = true

[[notifications.webhooks]]
name = "Discord Alerts"
url = "https://discord.com/api/webhooks/..."
webhook_type = "discord"
enabled = true

# Storage
[storage]
retain_days = 30
export_format = "json"
```

### Advanced Features

#### Multiple Repositories

```toml
[[repositories]]
name = "frontend"
url = "https://github.com/company/frontend.git"
branches = ["main", "staging"]
ecosystems = ["npm"]

[[repositories]]
name = "backend"
url = "https://github.com/company/backend.git"
branches = ["main", "develop"]
ecosystems = ["pypi", "go"]

[[repositories]]
name = "mobile"
url = "https://github.com/company/mobile.git"
branches = ["main"]
ecosystems = ["maven", "nuget"]
```

#### Custom Scheduling

```toml
[schedule]
frequency = "custom"
# Every 6 hours during business days
time = "0 */6 * * 1-5"
timezone = "America/New_York"
```

#### Security Policies

```toml
[[policies]]
name = "Critical Authentication Issues"
enabled = true

[policies.conditions]
title_contains = ["authentication", "auth", "login"]
severity = ["high", "critical"]

[policies.actions]
notify = true
priority = "critical"
custom_message = "🚨 Critical auth vulnerability detected!"
```

## Common Use Cases

### 1. Production Monitoring

Monitor critical production repositories with immediate alerts:

```toml
[[repositories]]
name = "production-api"
url = "https://github.com/company/api.git"
branches = ["main"]

[schedule]
frequency = "hourly"

[notifications.filters]
min_severity = "high"
only_new_vulnerabilities = true

[[policies]]
name = "Production Critical"
enabled = true
[policies.conditions]
severity = ["critical"]
[policies.actions]
notify = true
priority = "critical"
```

### 2. Development Team Alerts

Daily monitoring with team notifications:

```toml
[schedule]
frequency = "daily"
time = "09:00"
timezone = "America/New_York"

[[notifications.webhooks]]
name = "Dev Team Slack"
url = "https://hooks.slack.com/services/..."
webhook_type = "slack"
enabled = true

[notifications.filters]
min_severity = "medium"
```

### 3. Multi-Project Portfolio

Monitor multiple projects with different policies:

```toml
[[repositories]]
name = "web-frontend"
ecosystems = ["npm"]

[[repositories]]
name = "api-backend"
ecosystems = ["pypi", "go"]

[[repositories]]
name = "mobile-app"
ecosystems = ["maven"]

# Different policies for different project types
[[policies]]
name = "Frontend XSS Detection"
[policies.conditions]
title_contains = ["xss", "cross-site"]
ecosystems = ["npm"]

[[policies]]
name = "Backend Injection Vulnerabilities"
[policies.conditions]
title_contains = ["injection", "sql"]
ecosystems = ["pypi", "go"]
```

## Management Commands

### Status Monitoring

```bash
# Check automation status
vulfy automation status

# Validate configuration
vulfy automation validate

# Manual scan
vulfy automation run
```

### Debugging

```bash
# Run in foreground with debug logging
VULFY_LOG=debug vulfy automation start --foreground

# Test specific repository
vulfy automation run --repository my-web-app

# Check webhook connectivity
vulfy automation validate
```

## Best Practices

### Repository Configuration

1. **Use specific branches** - Don't monitor all branches unnecessarily
2. **Filter ecosystems** - Only scan relevant package managers per repo
3. **Set up credentials** - Use tokens for private repositories
4. **Test connectivity** - Validate repository access before scheduling

### Notification Management

1. **Set severity thresholds** - Avoid notification fatigue
2. **Use "new vulnerabilities only"** - Prevent repeated alerts
3. **Test webhooks** - Verify Discord/Slack integration works
4. **Create focused policies** - Target specific vulnerability types

### Performance Optimization

1. **Schedule appropriately** - Hourly for critical, daily for most projects
2. **Use workspace efficiently** - Clean up old repository clones
3. **Monitor resource usage** - Automation runs in background
4. **Limit concurrent scans** - Avoid overwhelming OSV.dev API

### Security Considerations

1. **Secure credentials** - Use environment variables for tokens
2. **Limit webhook access** - Use dedicated channels for security alerts
3. **Review policies regularly** - Update filtering rules as needed
4. **Monitor logs** - Check for authentication or API issues

## Troubleshooting

### Common Issues

**Scheduler not starting**
- Check configuration file syntax with `vulfy automation validate`
- Verify repository access and credentials
- Check webhook URLs are valid

**No notifications received**
- Verify webhook URLs and test with `vulfy automation validate`
- Check severity filters aren't too restrictive
- Ensure "only new vulnerabilities" isn't blocking all alerts

**Repository clone failures**
- Verify Git credentials and repository access
- Check network connectivity and firewall settings
- Ensure workspace directory is writable

**High resource usage**
- Reduce scan frequency for non-critical repositories
- Limit number of concurrent repository scans
- Clean up old workspace directories

### Getting Help

- **Configuration Issues**: [Configuration Guide](configuration.md)
- **Notification Setup**: [Notifications Guide](notifications.md)
- **Policy Creation**: [Security Policies Guide](security-policies.md)
- **GitHub Issues**: [Report Problems](https://github.com/mindPatch/vulfy/issues)

---

**Next**: [Repository Monitoring](repository-monitoring.md) - Detailed Git integration guide 