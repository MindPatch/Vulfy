# CI/CD Integration Guide

Integrate Vulfy into your continuous integration and deployment pipelines for automated security scanning.

## Overview

Vulfy is designed to work seamlessly in CI/CD environments with:

- **Fast execution** - Optimized for CI/CD performance
- **Multiple output formats** - JSON, SARIF, CSV for different tools
- **Configurable exit codes** - Fail builds on vulnerabilities
- **Quiet mode** - Minimal output for clean logs
- **Flexible filtering** - Focus on critical issues

## Exit Codes

Vulfy uses standard exit codes for CI/CD integration:

| Exit Code | Meaning | Action |
|-----------|---------|--------|
| `0` | No vulnerabilities found | Continue build |
| `1` | Vulnerabilities found or scan error | Fail build (configurable) |
| `2` | Invalid command line arguments | Fix configuration |

## Basic Integration Pattern

```bash
# Basic scan that fails on any vulnerability
vulfy scan packages --quiet || exit 1

# Only fail on high-severity vulnerabilities
vulfy scan packages --high-only --quiet || exit 1

# Generate reports but don't fail build
vulfy scan packages --format json --output security-report.json
vulfy scan packages --format sarif --output vulfy.sarif
```

## GitHub Actions

### Basic Workflow

Create `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  vulnerability-scan:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Download Vulfy
      run: |
        curl -LO https://github.com/mindPatch/vulfy/releases/latest/download/vulfy-linux-x86_64.tar.gz
        tar -xzf vulfy-linux-x86_64.tar.gz
        chmod +x vulfy
        sudo mv vulfy /usr/local/bin/
        
    - name: Run vulnerability scan
      run: |
        vulfy scan packages --format json --output vulfy-report.json
        vulfy scan packages --format sarif --output vulfy.sarif
        
    - name: Upload SARIF to GitHub Security tab
      uses: github/codeql-action/upload-sarif@v3
      if: always()
      with:
        sarif_file: vulfy.sarif
        
    - name: Upload scan results
      uses: actions/upload-artifact@v4
      if: always()
      with:
        name: vulnerability-reports
        path: |
          vulfy-report.json
          vulfy.sarif
```

### Advanced Workflow with Failure Conditions

```yaml
name: Security Scan (Advanced)

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  vulnerability-scan:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Vulfy
      run: |
        curl -LO https://github.com/mindPatch/vulfy/releases/latest/download/vulfy-linux-x86_64.tar.gz
        tar -xzf vulfy-linux-x86_64.tar.gz
        chmod +x vulfy
        sudo mv vulfy /usr/local/bin/
        
    - name: Run full vulnerability scan
      run: |
        # Generate comprehensive reports
        vulfy scan packages --format json --output vulfy-full-report.json
        vulfy scan packages --format sarif --output vulfy.sarif
        vulfy scan packages --format csv --output vulfy-report.csv
        
    - name: Check for high-severity vulnerabilities
      run: |
        # Fail build if high-severity vulnerabilities found
        echo "Checking for high-severity vulnerabilities..."
        if ! vulfy scan packages --high-only --quiet; then
          echo "❌ High-severity vulnerabilities found!"
          echo "Please review the security report and update vulnerable packages."
          exit 1
        else
          echo "✅ No high-severity vulnerabilities found."
        fi
        
    - name: Upload SARIF to GitHub Security tab
      uses: github/codeql-action/upload-sarif@v3
      if: always()
      with:
        sarif_file: vulfy.sarif
        
    - name: Comment PR with results
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v7
      with:
        script: |
          const fs = require('fs');
          const report = JSON.parse(fs.readFileSync('vulfy-full-report.json', 'utf8'));
          
          const comment = `## 🛡️ Vulnerability Scan Results
          
          **Summary:**
          - Total packages: ${report.summary.total_packages}
          - Vulnerable packages: ${report.summary.vulnerable_packages}
          - Total vulnerabilities: ${report.summary.total_vulnerabilities}
          
          **Severity Breakdown:**
          - 🔥 High: ${report.summary.severity_counts.high || 0}
          - 🟡 Medium: ${report.summary.severity_counts.medium || 0}
          - 🟢 Low: ${report.summary.severity_counts.low || 0}
          
          ${report.summary.total_vulnerabilities > 0 ? 
            '⚠️ Please review the vulnerabilities and update affected packages.' : 
            '✅ No vulnerabilities found!'}
          `;
          
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: comment
          });
        
    - name: Upload reports
      uses: actions/upload-artifact@v4
      if: always()
      with:
        name: vulnerability-reports
        path: |
          vulfy-full-report.json
          vulfy.sarif
          vulfy-report.csv
```

### Scheduled Scans

```yaml
name: Scheduled Security Scan

on:
  schedule:
    # Run daily at 2 AM UTC
    - cron: '0 2 * * *'
  workflow_dispatch: # Allow manual trigger

jobs:
  scheduled-scan:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Vulfy
      run: |
        curl -LO https://github.com/mindPatch/vulfy/releases/latest/download/vulfy-linux-x86_64.tar.gz
        tar -xzf vulfy-linux-x86_64.tar.gz
        chmod +x vulfy
        sudo mv vulfy /usr/local/bin/
        
    - name: Run vulnerability scan
      run: |
        vulfy scan packages --format json --output daily-scan-report.json
        
    - name: Create issue for new vulnerabilities
      if: always()
      uses: actions/github-script@v7
      with:
        script: |
          const fs = require('fs');
          const report = JSON.parse(fs.readFileSync('daily-scan-report.json', 'utf8'));
          
          if (report.summary.total_vulnerabilities > 0) {
            const highSeverity = report.summary.severity_counts.high || 0;
            const criticalSeverity = report.summary.severity_counts.critical || 0;
            
            if (highSeverity > 0 || criticalSeverity > 0) {
              await github.rest.issues.create({
                owner: context.repo.owner,
                repo: context.repo.repo,
                title: `🚨 Security Alert: ${highSeverity + criticalSeverity} High/Critical Vulnerabilities Found`,
                body: `Daily security scan found ${report.summary.total_vulnerabilities} vulnerabilities:
                
                - 🔥 Critical: ${criticalSeverity}
                - 🔥 High: ${highSeverity}
                - 🟡 Medium: ${report.summary.severity_counts.medium || 0}
                - 🟢 Low: ${report.summary.severity_counts.low || 0}
                
                Please review and update vulnerable packages immediately.
                
                Scan Date: ${new Date().toISOString()}`,
                labels: ['security', 'vulnerability']
              });
            }
          }
```

## GitLab CI

### Basic Pipeline

Create `.gitlab-ci.yml`:

```yaml
stages:
  - security-scan

variables:
  VULFY_VERSION: "latest"

security-scan:
  stage: security-scan
  image: ubuntu:latest
  
  before_script:
    - apt-get update -qq && apt-get install -y -qq curl
    - curl -LO https://github.com/mindPatch/vulfy/releases/latest/download/vulfy-linux-x86_64.tar.gz
    - tar -xzf vulfy-linux-x86_64.tar.gz
    - chmod +x vulfy
    - mv vulfy /usr/local/bin/
    
  script:
    - echo "Running vulnerability scan..."
    - vulfy scan packages --format json --output vulfy-report.json
    - vulfy scan packages --format sarif --output vulfy.sarif
    
  after_script:
    - |
      if [ -f vulfy-report.json ]; then
        echo "Vulnerability scan completed. Check artifacts for detailed results."
      fi
    
  artifacts:
    reports:
      sast: vulfy.sarif
    paths:
      - vulfy-report.json
      - vulfy.sarif
    expire_in: 1 week
    
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
    - if: $CI_MERGE_REQUEST_ID
```

### Advanced Pipeline with Failure Conditions

```yaml
stages:
  - security-scan
  - security-gate

variables:
  VULFY_VERSION: "latest"

.vulfy-setup: &vulfy-setup
  before_script:
    - apt-get update -qq && apt-get install -y -qq curl jq
    - curl -LO https://github.com/mindPatch/vulfy/releases/latest/download/vulfy-linux-x86_64.tar.gz
    - tar -xzf vulfy-linux-x86_64.tar.gz
    - chmod +x vulfy
    - mv vulfy /usr/local/bin/

security-scan:
  stage: security-scan
  image: ubuntu:latest
  <<: *vulfy-setup
  
  script:
    - echo "Running comprehensive vulnerability scan..."
    - vulfy scan packages --format json --output vulfy-report.json
    - vulfy scan packages --format sarif --output vulfy.sarif
    - vulfy scan packages --format csv --output vulfy-report.csv
    
    # Generate summary for merge request
    - |
      if [ -n "$CI_MERGE_REQUEST_ID" ]; then
        TOTAL_VULNS=$(jq '.summary.total_vulnerabilities' vulfy-report.json)
        HIGH_VULNS=$(jq '.summary.severity_counts.high // 0' vulfy-report.json)
        echo "Found $TOTAL_VULNS total vulnerabilities ($HIGH_VULNS high severity)"
      fi
    
  artifacts:
    reports:
      sast: vulfy.sarif
    paths:
      - vulfy-report.json
      - vulfy.sarif
      - vulfy-report.csv
    expire_in: 1 week

security-gate:
  stage: security-gate
  image: ubuntu:latest
  <<: *vulfy-setup
  
  script:
    - echo "Checking security gate..."
    - |
      if ! vulfy scan packages --high-only --quiet; then
        echo "❌ Security gate failed: High-severity vulnerabilities found!"
        echo "Please update vulnerable packages before merging."
        exit 1
      else
        echo "✅ Security gate passed: No high-severity vulnerabilities found."
      fi
  
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
    - if: $CI_MERGE_REQUEST_ID
  
  dependencies:
    - security-scan
```

## Jenkins

### Declarative Pipeline

Create `Jenkinsfile`:

```groovy
pipeline {
    agent any
    
    environment {
        VULFY_VERSION = 'latest'
    }
    
    stages {
        stage('Setup Vulfy') {
            steps {
                script {
                    sh '''
                        curl -LO https://github.com/mindPatch/vulfy/releases/latest/download/vulfy-linux-x86_64.tar.gz
                        tar -xzf vulfy-linux-x86_64.tar.gz
                        chmod +x vulfy
                        sudo mv vulfy /usr/local/bin/ || mv vulfy ./vulfy
                    '''
                }
            }
        }
        
        stage('Vulnerability Scan') {
            steps {
                script {
                    sh '''
                        echo "Running vulnerability scan..."
                        ./vulfy scan packages --format json --output vulfy-report.json || true
                        ./vulfy scan packages --format sarif --output vulfy.sarif || true
                        ./vulfy scan packages --format csv --output vulfy-report.csv || true
                    '''
                }
            }
        }
        
        stage('Security Gate') {
            steps {
                script {
                    def scanResult = sh(
                        script: './vulfy scan packages --high-only --quiet',
                        returnStatus: true
                    )
                    
                    if (scanResult != 0) {
                        currentBuild.result = 'UNSTABLE'
                        error('High-severity vulnerabilities found! Please review and update packages.')
                    } else {
                        echo '✅ No high-severity vulnerabilities found.'
                    }
                }
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'vulfy-*.json,vulfy.sarif,vulfy-*.csv', fingerprint: true
            
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: '.',
                reportFiles: 'vulfy-report.json',
                reportName: 'Vulnerability Report'
            ])
        }
        
        unstable {
            emailext (
                subject: "Security Alert: Vulnerabilities found in ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: """
                High-severity vulnerabilities were found in the latest scan.
                
                Build: ${env.BUILD_URL}
                Project: ${env.JOB_NAME}
                
                Please review the vulnerability report and update affected packages.
                """,
                to: "${env.CHANGE_AUTHOR_EMAIL},security-team@company.com"
            )
        }
    }
}
```

## Azure DevOps

### Basic Pipeline

Create `azure-pipelines.yml`:

```yaml
trigger:
  branches:
    include:
      - main
      - develop

pr:
  branches:
    include:
      - main

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: Bash@3
  displayName: 'Setup Vulfy'
  inputs:
    targetType: 'inline'
    script: |
      curl -LO https://github.com/mindPatch/vulfy/releases/latest/download/vulfy-linux-x86_64.tar.gz
      tar -xzf vulfy-linux-x86_64.tar.gz
      chmod +x vulfy
      sudo mv vulfy /usr/local/bin/

- task: Bash@3
  displayName: 'Run Vulnerability Scan'
  inputs:
    targetType: 'inline'
    script: |
      echo "Running vulnerability scan..."
      vulfy scan packages --format json --output $(Agent.TempDirectory)/vulfy-report.json
      vulfy scan packages --format sarif --output $(Agent.TempDirectory)/vulfy.sarif

- task: Bash@3
  displayName: 'Security Gate Check'
  inputs:
    targetType: 'inline'
    script: |
      if ! vulfy scan packages --high-only --quiet; then
        echo "##vso[task.logissue type=error]High-severity vulnerabilities found!"
        echo "##vso[task.complete result=Failed;]Security gate failed"
      else
        echo "✅ Security gate passed"
      fi

- task: PublishTestResults@2
  displayName: 'Publish SARIF Results'
  inputs:
    testResultsFormat: 'VSTest'
    testResultsFiles: '$(Agent.TempDirectory)/vulfy.sarif'
    failTaskOnFailedTests: false
  condition: always()

- task: PublishBuildArtifacts@1
  displayName: 'Publish Vulnerability Reports'
  inputs:
    pathToPublish: '$(Agent.TempDirectory)'
    artifactName: 'vulnerability-reports'
  condition: always()
```

## CircleCI

### Basic Configuration

Create `.circleci/config.yml`:

```yaml
version: 2.1

jobs:
  vulnerability-scan:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      
      - run:
          name: Setup Vulfy
          command: |
            curl -LO https://github.com/mindPatch/vulfy/releases/latest/download/vulfy-linux-x86_64.tar.gz
            tar -xzf vulfy-linux-x86_64.tar.gz
            chmod +x vulfy
            sudo mv vulfy /usr/local/bin/
      
      - run:
          name: Run Vulnerability Scan
          command: |
            vulfy scan packages --format json --output vulfy-report.json
            vulfy scan packages --format sarif --output vulfy.sarif
      
      - run:
          name: Security Gate
          command: |
            if ! vulfy scan packages --high-only --quiet; then
              echo "High-severity vulnerabilities found!"
              exit 1
            fi
      
      - store_artifacts:
          path: vulfy-report.json
          destination: vulnerability-reports/
      
      - store_artifacts:
          path: vulfy.sarif
          destination: vulnerability-reports/

workflows:
  security-scan:
    jobs:
      - vulnerability-scan:
          filters:
            branches:
              only:
                - main
                - develop
```

## Docker Integration

### Multi-stage Dockerfile

```dockerfile
# Security scan stage
FROM ubuntu:latest AS security-scan

RUN apt-get update && apt-get install -y curl && \
    curl -LO https://github.com/mindPatch/vulfy/releases/latest/download/vulfy-linux-x86_64.tar.gz && \
    tar -xzf vulfy-linux-x86_64.tar.gz && \
    chmod +x vulfy && \
    mv vulfy /usr/local/bin/

COPY package*.json ./
COPY requirements.txt ./
COPY Cargo.toml Cargo.lock ./

RUN vulfy scan packages --format json --output /tmp/vulfy-report.json && \
    vulfy scan packages --high-only --quiet

# Application stage
FROM node:18-alpine AS app
# ... rest of your application build
```

### Standalone Security Scan Container

```dockerfile
FROM ubuntu:latest

RUN apt-get update && apt-get install -y curl jq && \
    curl -LO https://github.com/mindPatch/vulfy/releases/latest/download/vulfy-linux-x86_64.tar.gz && \
    tar -xzf vulfy-linux-x86_64.tar.gz && \
    chmod +x vulfy && \
    mv vulfy /usr/local/bin/ && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /scan

ENTRYPOINT ["vulfy"]
CMD ["scan", "packages", "--format", "json"]
```

Usage:
```bash
# Scan current directory
docker run -v $(pwd):/scan vulfy-scanner

# Scan with custom options
docker run -v $(pwd):/scan vulfy-scanner scan packages --high-only --format sarif --output vulfy.sarif
```

## Best Practices

### Performance Optimization

1. **Cache Vulfy Binary**: Download once, reuse across jobs
2. **Parallel Execution**: Run scans in parallel with other tests
3. **Selective Scanning**: Use `--ecosystems` to limit scope
4. **Quiet Mode**: Use `--quiet` to reduce log noise

### Security Gate Strategy

1. **Fail on High/Critical**: Block deployments for severe issues
2. **Warn on Medium**: Generate reports but allow deployment
3. **Track All Issues**: Store all vulnerability data for trending

### Report Management

1. **Multiple Formats**: Generate JSON for automation, SARIF for tools
2. **Artifact Storage**: Keep reports for compliance and trending
3. **Notification Strategy**: Alert security teams on new issues

### Example Security Gate Logic

```bash
#!/bin/bash
# security-gate.sh

echo "Running security gate checks..."

# Check for critical/high vulnerabilities
if ! vulfy scan packages --high-only --quiet; then
    echo "❌ SECURITY GATE FAILED: High/Critical vulnerabilities found"
    echo "Deployment blocked. Please update vulnerable packages."
    exit 1
fi

# Generate reports for tracking
vulfy scan packages --format json --output security-report.json
vulfy scan packages --format sarif --output vulfy.sarif

# Check total vulnerability count
TOTAL_VULNS=$(jq '.summary.total_vulnerabilities' security-report.json)

if [ "$TOTAL_VULNS" -gt 10 ]; then
    echo "⚠️  WARNING: $TOTAL_VULNS total vulnerabilities found"
    echo "Consider addressing medium/low severity issues"
fi

echo "✅ Security gate passed"
exit 0
```

---

**Next**: [Automation Setup](automation-setup.md) - Complete automation configuration guide 