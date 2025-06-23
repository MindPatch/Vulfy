# 🐺 Vulfy

**Fast, cross-language vulnerability scanner that doesn't mess around.**

*Current Version: v0.1.0*

---

## What's This Thing Do?

Vulfy sniffs out vulnerable packages in your projects faster than you can say "supply chain attack." It's like having a security-obsessed teammate who never sleeps and knows every CVE by heart.

Born from frustration with slow, bloated security tools that take forever to tell you what you already suspect: *yes, your dependencies probably have issues.*

## The Goods

🔥 **Lightning Fast** - Async Rust goes brrrr  
🌍 **Multi-Ecosystem** - npm, pip, cargo, maven, go, ruby - we got 'em all  
📊 **Multiple Outputs** - Pretty tables, JSON, CSV, SARIF, whatever floats your boat  
🎯 **OSV.dev Integration** - Real vulnerability data, not snake oil  
⚡ **Zero Config** - Point, shoot, done  

## Quick Start

```bash
# Clone and build
$ git clone https://github.com/mindPatch/vulfy.git
$ cd vulfy
$ cargo build --release

# Scan your project (the pretty way)
$ vulfy

vulfy scan packages [OPTIONS]
OPTIONS:
    -p, --path <PATH>              Where to scan [default: current directory]
    -f, --format <FORMAT>          Output format: table, json, csv, summary, sarif
    -o, --output <FILE>            Save to file instead of stdout
    -e, --ecosystems <LIST>        Only scan specific ecosystems (npm,pypi,cargo,etc)
    -q, --quiet                    Shut up and scan
    --high-only                    Only show the scary vulnerabilities
    --no-recursive                 Don't dig into subdirectories
    --no-dev-deps                  Skip development dependencies
```

## What Gets Scanned

| Ecosystem | Files We Hunt |
|-----------|---------------|
| 📦 **npm** | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `package.json`, `pnpm-lock.yaml` |
| 🐍 **Python** | `requirements.txt`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `pyproject.toml`, `setup.py`, `setup.cfg`, `environment.yml` (conda) |
| 🦀 **Rust** | `Cargo.lock`, `Cargo.toml` |
| ☕ **Java** | `pom.xml`, `build.gradle`, `build.gradle.kts`, `ivy.xml` |
| 🐹 **Go** | `go.mod`, `go.sum`, `go.work`, `go.work.sum`, `vendor/modules.txt` |
| 💎 **Ruby** | `Gemfile.lock`, `Gemfile`, `gems.rb`, `*.gemspec` |

## Real Talk Examples

### The Beautiful Default (Table Format)
```bash
vulfy scan packages
```
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
• Total packages: 42
• Vulnerable packages: 8
• Total vulnerabilities: 12
• High severity: 4 🔥
• Medium severity: 6 🟡
• Low severity: 2 🟢
```

### For Your CI/CD Pipeline
```bash
vulfy scan packages --format json --quiet > security-report.json
```

### Integration with GitHub Security
```bash
vulfy scan packages --format sarif -o vulfy.sarif
# Upload vulfy.sarif to GitHub Security tab
```


## What's Coming Next

🚀 **Future Features (because we're just getting started):**

- **🔧 Fix Mode** - Auto-update vulnerable packages to safe versions
- **📈 Trend Analysis** - Track vulnerability trends over time
- **🎯 Custom Rules** - Define your own vulnerability policies
- **⚡ Watch Mode** - Monitor projects in real-time for new vulnerabilities
- **🔗 More Ecosystems** - C/C++ (vcpkg), PHP (composer), .NET (NuGet)
- **🌐 Web Dashboard** - Beautiful web interface for teams
- **🔔 Notifications** - Slack/Discord/email alerts for new vulnerabilities
- **📋 Policy Engine** - Fail builds based on severity thresholds
- **🐳 Docker Image Scans** - Deep dive into container layers and installed packages
- **🗂️ File System Scanning** - Scan entire systems for vulnerable packages
- **📡 Git Repository Monitoring** - Continuous scanning of repos for new vulnerabilities
- **💽 VirtualBox Disk Analysis** - Mount and scan VM disks for security issues

Got ideas? Drop an issue and let's make it happen!

## Technical Stuff

**Built With:**
- Rust 2021 (because performance matters)
- Tokio (async all the things)
- OSV.dev API (real vulnerability data)
- A healthy disrespect for slow tools

**Architecture:**
- Strategy pattern for different parsers
- Concurrent vulnerability checking (10 requests at once, we're not animals)
- Memory efficient streaming for large projects
- SARIF 2.1.0 compliant output

## Contributing

Found a bug? Want a feature? Know a language we should support?

1. Fork it
2. Fix it
3. PR it
4. 🎉

No complicated contributor agreements or corporate BS. Just make it better.

## The Fine Print

MIT License - do whatever you want with it.
