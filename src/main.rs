//! TLS Certificate Analyzer CLI
//!
//! Command-line interface for the TLS certificate analyzer.

use clap::{Parser, Subcommand};
use tls_cert_analyzer::output::OutputFormat;
use anyhow::Result;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "tls-cert-analyzer")]
#[command(author = "Prateek Yadav")]
#[command(version = tls_cert_analyzer::VERSION)]
#[command(about = "Graduate-level TLS certificate security analyzer", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a single TLS certificate
    Analyze {
        /// Host to analyze (host:port format, e.g., google.com:443)
        #[arg(value_name = "HOST:PORT")]
        target: String,

        /// Output format
        #[arg(short, long, value_name = "FORMAT", default_value = "text")]
        format: OutputFormat,

        /// Output file (default: stdout)
        #[arg(short, long, value_name = "FILE")]
        output: Option<std::path::PathBuf>,
    },

    /// Scan multiple hosts from a file
    Scan {
        /// File containing hosts (one per line, host:port format)
        #[arg(short = 'H', long, value_name = "FILE")]
        hosts: std::path::PathBuf,

        /// Number of concurrent scans
        #[arg(short, long, value_name = "N", default_value = "10")]
        concurrency: usize,

        /// Output format
        #[arg(short, long, value_name = "FORMAT", default_value = "table")]
        format: OutputFormat,

        /// Output file (default: stdout)
        #[arg(short, long, value_name = "FILE")]
        output: Option<std::path::PathBuf>,
    },

    /// Security audit mode (strict checking)
    Audit {
        /// Host to audit (host:port format)
        #[arg(value_name = "HOST:PORT")]
        target: String,

        /// Strict mode (fail on any warning)
        #[arg(long)]
        strict: bool,

        /// Output format
        #[arg(short, long, value_name = "FORMAT", default_value = "text")]
        format: OutputFormat,
    },

    /// Export certificate chain
    Export {
        /// Host to export from (host:port format)
        #[arg(value_name = "HOST:PORT")]
        target: String,

        /// Output file
        #[arg(short, long, value_name = "FILE")]
        output: std::path::PathBuf,

        /// Export leaf certificate only (not full chain)
        #[arg(long)]
        leaf_only: bool,
    },
}

async fn analyze_command(target: String, format: OutputFormat, output: Option<std::path::PathBuf>) -> Result<()> {
    use tls_cert_analyzer::{CertificateFetcher, CertificateAnalyzer};
    use tls_cert_analyzer::cert::parser::parse_certificate;
    use colored::Colorize;

    println!("{} Analyzing certificate for {}...", "🔍".cyan(), target.bold());

    // Parse target (host:port)
    let (host, port) = parse_target(&target)?;

    // Fetch certificates
    let fetcher = CertificateFetcher::new();
    println!("  {} Connecting to {}:{}...", "→".blue(), host, port);
    let cert_chain = fetcher.fetch(host, port).await?;
    println!("  {} Retrieved {} certificate(s)", "✓".green(), cert_chain.len());

    // Parse certificates
    println!("  {} Parsing certificates...", "→".blue());
    let mut parsed_certs = Vec::new();
    for (i, der) in cert_chain.iter().enumerate() {
        match parse_certificate(der) {
            Ok(cert) => parsed_certs.push(cert),
            Err(e) => eprintln!("  {} Warning: Failed to parse certificate {}: {}", "⚠".yellow(), i, e),
        }
    }

    if parsed_certs.is_empty() {
        return Err(anyhow::anyhow!("No valid certificates found"));
    }

    // Analyze certificates
    println!("  {} Analyzing security issues...", "→".blue());
    let analyzer = CertificateAnalyzer::new();
    let mut results = Vec::new();
    for cert in &parsed_certs {
        let result = analyzer.analyze(cert)?;
        results.push(result);
    }

    // Format output
    let formatter = tls_cert_analyzer::output::get_formatter(format);
    let output_text = formatter.format(&results)?;

    // Write output
    if let Some(path) = output {
        std::fs::write(&path, &output_text)?;
        println!("\n{} Results written to {}", "✓".green(), path.display());
    } else {
        println!("\n{}", output_text);
    }

    // Summary
    let total_findings: usize = results.iter().map(|r| r.findings.len()).sum();
    let has_critical = results.iter().any(|r| r.has_critical_findings());

    if has_critical {
        println!("\n{} {} critical issue(s) found!", "⚠".red().bold(),
                 results.iter().filter(|r| r.has_critical_findings()).count());
    } else if total_findings > 0 {
        println!("\n{} {} issue(s) found", "ℹ".yellow(), total_findings);
    } else {
        println!("\n{} No security issues detected", "✓".green());
    }

    Ok(())
}

async fn scan_command(hosts_file: std::path::PathBuf, concurrency: usize, format: OutputFormat, output: Option<std::path::PathBuf>) -> Result<()> {
    use tls_cert_analyzer::{CertificateFetcher, CertificateAnalyzer};
    use tls_cert_analyzer::cert::parser::parse_certificate;
    use colored::Colorize;
    use tokio::task::JoinSet;

    println!("{} Scanning hosts from {}...", "📊".cyan(), hosts_file.display());

    // Read hosts file
    let content = std::fs::read_to_string(&hosts_file)?;
    let hosts: Vec<String> = content.lines()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .map(String::from)
        .collect();

    println!("  {} Loaded {} host(s)", "✓".green(), hosts.len());
    println!("  {} Concurrency: {}", "→".blue(), concurrency);

    let mut all_results = Vec::new();

    let pb = indicatif::ProgressBar::new(hosts.len() as u64);
    pb.set_style(indicatif::ProgressStyle::default_bar()
        .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
        .unwrap()
        .progress_chars("#>-"));

    // Process hosts with limited concurrency
    let mut join_set = JoinSet::new();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));

    for target in hosts {
        let fetcher_clone = CertificateFetcher::new();
        let analyzer_clone = CertificateAnalyzer::new();
        let permit = semaphore.clone().acquire_owned().await.unwrap();

        join_set.spawn(async move {
            let result = async {
                let (host, port) = parse_target(&target)
                    .map_err(|e| tls_cert_analyzer::error::CertAnalyzerError::InvalidInput(e.to_string()))?;
                let cert_chain = fetcher_clone.fetch(host, port).await?;
                let parsed = parse_certificate(&cert_chain[0])?;
                analyzer_clone.analyze(&parsed)
            }.await;
            drop(permit);
            (target, result)
        });
    }

    // Collect results
    while let Some(res) = join_set.join_next().await {
        match res {
            Ok((target, Ok(analysis))) => {
                all_results.push(analysis);
                pb.set_message(format!("{} ✓", target));
            }
            Ok((target, Err(e))) => {
                pb.set_message(format!("{} ✗ ({})", target, e));
            }
            Err(e) => {
                pb.set_message(format!("Task error: {}", e));
            }
        }
        pb.inc(1);
    }

    pb.finish_with_message("Scan complete");

    // Format output
    let formatter = tls_cert_analyzer::output::get_formatter(format);
    let output_text = formatter.format(&all_results)?;

    // Write output
    if let Some(path) = output {
        std::fs::write(&path, &output_text)?;
        println!("\n{} Results written to {}", "✓".green(), path.display());
    } else {
        println!("\n{}", output_text);
    }

    println!("\n{} Scanned {} hosts successfully", "✓".green(), all_results.len());

    Ok(())
}

async fn audit_command(target: String, strict: bool, format: OutputFormat) -> Result<()> {
    use tls_cert_analyzer::{CertificateFetcher, CertificateAnalyzer};
    use tls_cert_analyzer::cert::parser::parse_certificate;
    use tls_cert_analyzer::analysis::Severity;
    use colored::Colorize;

    println!("{} Security audit for {}...", "🔒".cyan(), target.bold());
    if strict {
        println!("  {} Strict mode enabled (fail on any warning)", "⚠".yellow());
    }

    let (host, port) = parse_target(&target)?;

    let fetcher = CertificateFetcher::new();
    let cert_chain = fetcher.fetch(host, port).await?;

    let mut parsed_certs = Vec::new();
    for der in &cert_chain {
        parsed_certs.push(parse_certificate(der)?);
    }

    let analyzer = CertificateAnalyzer::new();
    let mut results = Vec::new();
    for cert in &parsed_certs {
        results.push(analyzer.analyze(cert)?);
    }

    // Format output
    let formatter = tls_cert_analyzer::output::get_formatter(format);
    let output_text = formatter.format(&results)?;
    println!("\n{}", output_text);

    // Audit verdict
    let has_critical = results.iter().any(|r| r.has_critical_findings());
    let has_high = results.iter().any(|r| {
        r.findings.iter().any(|f| f.severity == Severity::High)
    });
    let has_any_issues = results.iter().any(|r| !r.findings.is_empty());

    if has_critical {
        println!("\n{} AUDIT FAILED: Critical security issues detected", "✗".red().bold());
        std::process::exit(1);
    } else if has_high {
        println!("\n{} AUDIT WARNING: High severity issues detected", "⚠".yellow().bold());
        if strict {
            std::process::exit(1);
        }
    } else if has_any_issues && strict {
        println!("\n{} AUDIT FAILED: Issues detected (strict mode)", "✗".red().bold());
        std::process::exit(1);
    } else if has_any_issues {
        println!("\n{} AUDIT PASSED: Minor issues detected", "ℹ".yellow());
    } else {
        println!("\n{} AUDIT PASSED: No security issues detected", "✓".green().bold());
    }

    Ok(())
}

async fn export_command(target: String, output: std::path::PathBuf, leaf_only: bool) -> Result<()> {
    use tls_cert_analyzer::CertificateFetcher;
    use colored::Colorize;

    println!("{} Exporting certificates from {}...", "💾".cyan(), target.bold());

    let (host, port) = parse_target(&target)?;

    let fetcher = CertificateFetcher::new();
    let cert_chain = fetcher.fetch(host, port).await?;

    // Convert to PEM format
    let mut pem_data = String::new();
    let certs_to_export = if leaf_only {
        &cert_chain[..1]
    } else {
        &cert_chain[..]
    };

    for (i, der) in certs_to_export.iter().enumerate() {
        let cert = rustls::pki_types::CertificateDer::from(der.clone());

        pem_data.push_str("-----BEGIN CERTIFICATE-----\n");
        // Base64 encode the DER data
        let b64 = base64_encode(cert.as_ref());
        for chunk in b64.as_bytes().chunks(64) {
            pem_data.push_str(&String::from_utf8_lossy(chunk));
            pem_data.push('\n');
        }
        pem_data.push_str("-----END CERTIFICATE-----\n");

        if i < certs_to_export.len() - 1 {
            pem_data.push('\n');
        }
    }

    std::fs::write(&output, pem_data)?;

    println!("  {} Exported {} certificate(s) to {}",
             "✓".green(),
             certs_to_export.len(),
             output.display());

    Ok(())
}

fn parse_target(target: &str) -> Result<(&str, u16)> {
    if let Some((host, port_str)) = target.rsplit_once(':') {
        let port = port_str.parse::<u16>()
            .map_err(|_| anyhow::anyhow!("Invalid port: {}", port_str))?;
        Ok((host, port))
    } else {
        // Default to port 443 if not specified
        Ok((target, 443))
    }
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    const STANDARD: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::STANDARD;
    STANDARD.encode(data)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Set up logging
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    // Execute command
    match cli.command {
        Commands::Analyze { target, format, output } => {
            analyze_command(target, format, output).await?;
        }
        Commands::Scan { hosts, concurrency, format, output } => {
            scan_command(hosts, concurrency, format, output).await?;
        }
        Commands::Audit { target, strict, format } => {
            audit_command(target, strict, format).await?;
        }
        Commands::Export { target, output, leaf_only } => {
            export_command(target, output, leaf_only).await?;
        }
    }

    Ok(())
}
