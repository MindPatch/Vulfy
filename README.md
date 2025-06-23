# 🐺 Vulfy

**Blazingly fast, cross-language vulnerability scanner. No fluff, just facts.**
---

## 🚀 What Is Vulfy?

Vulfy is your no-nonsense security sidekick: it scans your project’s dependencies for known vulnerabilities—fast. Think of it as a hyperactive security analyst who knows every CVE ever published and never takes a coffee break.

Built out of frustration with sluggish, bloated tools that waste your time just to confirm your fears: *Yes, your packages are probably vulnerable.*

---

## ⚙️ Features

* 🔥 **Ridiculously Fast** — Built with async Rust. It flies.
* 🌍 **Multi-Language Support** — Works across npm, pip, Cargo, Maven, Go, Ruby, and more.
* 📊 **Flexible Output Formats** — Pretty tables, JSON, CSV, SARIF—take your pick.
* 🎯 **Powered by OSV.dev** — Real-time vulnerability data from the source.
* ⚡ **Zero Config** — Just point and scan.

---

## ⚡ Quick Start

```bash
# Clone and build
git clone https://github.com/mindPatch/vulfy.git
cd vulfy
cargo build --release

# Run a basic scan
./vulfy
```

### Command Options

```bash
vulfy scan packages [OPTIONS]

OPTIONS:
  -p, --path <PATH>           Directory to scan (default: current dir)
  -f, --format <FORMAT>       Output format: table, json, csv, sarif, summary
  -o, --output <FILE>         Write output to file
  -e, --ecosystems <LIST>     Filter by ecosystems (e.g. npm,pypi,cargo)
  -q, --quiet                 Suppress output except results
      --high-only             Only show high-severity vulnerabilities
      --no-recursive          Don’t scan subdirectories
      --no-dev-deps           Skip dev dependencies
```

---

## 📦 Ecosystem Coverage

| Ecosystem  | Files Detected                                    |
| ---------- | ------------------------------------------------- |
| **npm**    | `package-lock.json`, `yarn.lock`, `package.json`  |
| **Python** | `requirements.txt`, `Pipfile.lock`, `poetry.lock` |
| **Rust**   | `Cargo.lock`, `Cargo.toml`                        |
| **Java**   | `pom.xml`                                         |
| **Go**     | `go.mod`, `go.sum`                                |
| **Ruby**   | `Gemfile.lock`                                    |

---

## 🧪 Examples

### Table Output (Default)

```bash
vulfy scan packages
```

```
🔍 Scanning for package files...
📦 Found 6 files across 4 ecosystems

🛡️  VULNERABILITY REPORT
┌────────────────────────────┬────────────┬─────────┬────────────────┬──────┐
│ Title                      │ CVE ID     │ Severity│ Package        │ Year │
├────────────────────────────┼────────────┼─────────┼────────────────┼──────┤
│ Remote Code Exec in lodash│ CVE-2021-123│ 🔥 High │ lodash@4.17.0  │ 2021 │
│ Path Traversal in express │ CVE-2022-456│ 🟡 Med. │ express@4.16.0 │ 2022 │
└────────────────────────────┴────────────┴─────────┴────────────────┴──────┘

📊 SCAN SUMMARY
• Total packages: 42  
• Vulnerable: 8  
• Total CVEs: 12  
• High: 4 🔥, Medium: 6 🟡, Low: 2 🟢
```

### For CI/CD Pipelines

```bash
vulfy scan packages --format json --quiet > security-report.json
```

### GitHub Security Integration

```bash
vulfy scan packages --format sarif -o vulfy.sarif
# Upload 'vulfy.sarif' to GitHub’s Security tab
```

---

## 🔭 Roadmap

Coming soon:

* 🔧 Auto-Fix Mode – Suggest or apply patched versions
* 📈 Trend Reports – See how your project improves (or worsens) over time
* 🎯 Custom Rules – Enforce your own policies
* ⚡ Watch Mode – Real-time scanning
* 🔗 Support for More Ecosystems – vcpkg, composer, NuGet, etc.
* 🌐 Web UI – Central dashboard for teams
* 🔔 Alerts – Slack/Discord/email integrations
* 📋 Policy Engine – Block builds by severity thresholds
* 🐳 Docker & VM Scans – Dive into container layers or mounted disks
* 📡 Git Monitoring – Auto-scan new changes

Have an idea? [Open an issue](https://github.com/mindPatch/vulfy/issues) and help shape the future.

---

## 🛠️ Under the Hood

**Tech Stack:**

* Rust 2021 — fast and fearless
* Tokio — async concurrency
* OSV.dev API — the good stuff
* SARIF 2.1.0 output — for serious CI/CD integration

**Architecture Highlights:**

* Modular parser strategy per ecosystem
* Concurrent API querying (10 at a time, no more, no less)
* Efficient streaming for big lockfiles

---

## 🤝 Contributing

Pull requests welcome. Seriously.

1. Fork it
2. Make it better
3. PR it
4. 🎉 Done

No legal nonsense, no CLA walls. Just open source.

---

## 📄 License

MIT — Use it, fork it, profit from it, or break it. Your call.
