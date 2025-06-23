use std::path::PathBuf;
use git2::{Repository as GitRepository, Cred, RemoteCallbacks, FetchOptions};
use tracing::{info, debug};
use tokio::fs;
use anyhow::Result;
use crate::automation::{Repository, ScanResult};
use crate::scanner::Scanner;
use crate::types::ScanConfig;
use chrono::Utc;
use uuid::Uuid;

pub struct GitMonitor {
    scanner: Scanner,
    workspace_dir: PathBuf,
}

impl GitMonitor {
    pub fn new(workspace_dir: PathBuf) -> Self {
        Self {
            scanner: Scanner::new(),
            workspace_dir,
        }
    }

    /// Initialize the workspace directory
    pub async fn init_workspace(&self) -> Result<()> {
        if !self.workspace_dir.exists() {
            fs::create_dir_all(&self.workspace_dir).await?;
            info!("Created workspace directory: {}", self.workspace_dir.display());
        }
        Ok(())
    }

    /// Clone or update a repository and scan it
    pub async fn scan_repository(&self, repo_config: &Repository) -> Result<Vec<(ScanResult, Vec<crate::types::Package>)>> {
        let repo_dir = self.get_repo_directory(&repo_config.name);
        
        // Ensure the repository is up to date
        self.update_repository(repo_config, &repo_dir).await?;
        
        // Get branches to scan
        let branches = self.get_branches_to_scan(repo_config, &repo_dir)?;
        
        let mut results = Vec::new();
        
        for branch in branches {
            info!("Scanning repository '{}' on branch '{}'", repo_config.name, branch);
            
            // Checkout the specific branch
            self.checkout_branch(&repo_dir, &branch)?;
            
            // Perform the scan
            let (scan_result, packages) = self.perform_scan(repo_config, &repo_dir, &branch).await?;
            results.push((scan_result, packages));
        }
        
        Ok(results)
    }

    /// Get the local directory for a repository
    fn get_repo_directory(&self, repo_name: &str) -> PathBuf {
        self.workspace_dir.join(sanitize_repo_name(repo_name))
    }

    /// Clone or update a repository
    async fn update_repository(&self, repo_config: &Repository, repo_dir: &PathBuf) -> Result<()> {
        if repo_dir.exists() {
            // Repository exists, update it
            info!("Updating existing repository: {}", repo_config.name);
            self.pull_repository(repo_config, repo_dir)?;
        } else {
            // Repository doesn't exist, clone it
            info!("Cloning repository: {} from {}", repo_config.name, repo_config.url);
            self.clone_repository(repo_config, repo_dir)?;
        }
        Ok(())
    }

    /// Clone a repository
    fn clone_repository(&self, repo_config: &Repository, repo_dir: &PathBuf) -> Result<()> {
        let mut builder = git2::build::RepoBuilder::new();
        
        // Set up authentication if provided
        if let Some(credentials) = &repo_config.credentials {
            let mut callbacks = RemoteCallbacks::new();
            let creds = credentials.clone();
            
            callbacks.credentials(move |_url, username_from_url, _allowed_types| {
                if let Some(token) = &creds.token {
                    // Use token authentication (GitHub/GitLab)
                    let username = creds.username.as_deref().unwrap_or("git");
                    Cred::userpass_plaintext(username, token)
                } else if let Some(ssh_key) = &creds.ssh_key_path {
                    // Use SSH key authentication
                    let username = username_from_url.unwrap_or("git");
                    Cred::ssh_key(username, None, ssh_key, None)
                } else {
                    // Default authentication
                    Cred::default()
                }
            });
            
            let mut fetch_options = FetchOptions::new();
            fetch_options.remote_callbacks(callbacks);
            builder.fetch_options(fetch_options);
        }

        builder.clone(&repo_config.url, repo_dir)?;
        info!("Successfully cloned repository: {}", repo_config.name);
        Ok(())
    }

    /// Pull updates from a repository
    fn pull_repository(&self, repo_config: &Repository, repo_dir: &PathBuf) -> Result<()> {
        let repo = GitRepository::open(repo_dir)?;
        
        // Fetch from origin
        let mut remote = repo.find_remote("origin")?;
        
        // Set up authentication if provided
        let mut callbacks = RemoteCallbacks::new();
        if let Some(credentials) = &repo_config.credentials {
            let creds = credentials.clone();
            callbacks.credentials(move |_url, username_from_url, _allowed_types| {
                if let Some(token) = &creds.token {
                    let username = creds.username.as_deref().unwrap_or("git");
                    Cred::userpass_plaintext(username, token)
                } else if let Some(ssh_key) = &creds.ssh_key_path {
                    let username = username_from_url.unwrap_or("git");
                    Cred::ssh_key(username, None, ssh_key, None)
                } else {
                    Cred::default()
                }
            });
        }
        
        let mut fetch_options = FetchOptions::new();
        fetch_options.remote_callbacks(callbacks);
        
        remote.fetch(&[] as &[&str], Some(&mut fetch_options), None)?;
        
        info!("Successfully updated repository: {}", repo_config.name);
        Ok(())
    }

    /// Get the list of branches to scan
    fn get_branches_to_scan(&self, repo_config: &Repository, repo_dir: &PathBuf) -> Result<Vec<String>> {
        let repo = GitRepository::open(repo_dir)?;
        
        if let Some(configured_branches) = &repo_config.branches {
            // Use configured branches
            Ok(configured_branches.clone())
        } else {
            // Use default branch
            let head = repo.head()?;
            if let Some(branch_name) = head.shorthand() {
                Ok(vec![branch_name.to_string()])
            } else {
                Ok(vec!["main".to_string()]) // Fallback to main
            }
        }
    }

    /// Checkout a specific branch
    fn checkout_branch(&self, repo_dir: &PathBuf, branch_name: &str) -> Result<()> {
        let repo = GitRepository::open(repo_dir)?;
        
        // Find the branch (local or remote)
        let branch_ref = format!("refs/heads/{}", branch_name);
        let remote_branch_ref = format!("refs/remotes/origin/{}", branch_name);
        
        let object = if let Ok(reference) = repo.find_reference(&branch_ref) {
            reference.peel_to_commit()?.into_object()
        } else if let Ok(reference) = repo.find_reference(&remote_branch_ref) {
            // Create local branch from remote
            let commit = reference.peel_to_commit()?;
            repo.branch(branch_name, &commit, false)?;
            commit.into_object()
        } else {
            return Err(anyhow::anyhow!("Branch '{}' not found", branch_name));
        };
        
        repo.checkout_tree(&object, None)?;
        repo.set_head(&branch_ref)?;
        
        debug!("Checked out branch: {}", branch_name);
        Ok(())
    }

    /// Perform vulnerability scan on the repository
    async fn perform_scan(&self, repo_config: &Repository, repo_dir: &PathBuf, branch: &str) -> Result<(ScanResult, Vec<crate::types::Package>)> {
        let start_time = std::time::Instant::now();
        
        // Create scan configuration
        let scan_config = ScanConfig {
            target_path: repo_dir.clone(),
            output_file: None,
            recursive: true,
            ecosystems: repo_config.ecosystems.clone(),
            include_dev_dependencies: true,
            format: crate::types::ReportFormat::Json, // We'll process results programmatically
            quiet: true,
            high_only: false,
        };
        
        // Perform the scan
        let packages = self.scanner.scan_directory(&scan_config).await?;
        let total_packages = packages.len();
        
        // Get vulnerabilities for all packages
        let matcher = crate::matcher::VulnerabilityMatcher::new();
        let scan_result = matcher.check_vulnerabilities(packages.clone()).await?;
        
        // Extract vulnerabilities from scan result
        let vulnerabilities: Vec<crate::types::Vulnerability> = scan_result.packages
            .into_iter()
            .flat_map(|pkg| pkg.vulnerabilities)
            .collect();
        
        let duration = start_time.elapsed();
        
        // Create automation scan result
        let automation_scan_result = ScanResult {
            id: Uuid::new_v4().to_string(),
            repository: repo_config.name.clone(),
            branch: branch.to_string(),
            timestamp: Utc::now(),
            vulnerabilities,
            total_packages,
            scan_duration_ms: duration.as_millis() as u64,
            policies_applied: vec![], // This will be filled by the policy engine
        };
        
        info!("Scan completed for {}/{}: {} packages, {} vulnerabilities, took {}ms", 
               repo_config.name, branch, total_packages, automation_scan_result.vulnerabilities.len(), automation_scan_result.scan_duration_ms);
        
        Ok((automation_scan_result, packages))
    }
}

/// Sanitize repository name for use as directory name
fn sanitize_repo_name(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c => c,
        })
        .collect()
} 