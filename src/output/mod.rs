//! Output formatting module

use crate::analysis::AnalysisResult;
use crate::error::{CertAnalyzerError, Result};
use serde::{Deserialize, Serialize};

/// Output format options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputFormat {
    /// JSON format (machine-readable)
    Json,
    /// Table format (human-readable)
    Table,
    /// Detailed text format
    Text,
}

impl std::str::FromStr for OutputFormat {
    type Err = CertAnalyzerError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "table" => Ok(Self::Table),
            "text" => Ok(Self::Text),
            _ => Err(CertAnalyzerError::InvalidInput(format!(
                "Unknown output format: {s}"
            ))),
        }
    }
}

/// Output formatter trait
pub trait OutputFormatter {
    /// Format analysis results
    fn format(&self, results: &[AnalysisResult]) -> Result<String>;
}

/// JSON formatter
pub struct JsonFormatter;

impl OutputFormatter for JsonFormatter {
    fn format(&self, results: &[AnalysisResult]) -> Result<String> {
        serde_json::to_string_pretty(results)
            .map_err(|e| CertAnalyzerError::SerializationError(e.to_string()))
    }
}

/// Table formatter
pub struct TableFormatter;

impl OutputFormatter for TableFormatter {
    fn format(&self, results: &[AnalysisResult]) -> Result<String> {
        use tabled::{Table, Tabled};

        #[derive(Tabled)]
        struct Row {
            subject: String,
            severity: String,
            title: String,
        }

        let rows: Vec<Row> = results
            .iter()
            .flat_map(|result| {
                result.findings.iter().map(|finding| Row {
                    subject: result.subject.clone(),
                    severity: finding.severity.to_string(),
                    title: finding.title.clone(),
                })
            })
            .collect();

        if rows.is_empty() {
            return Ok("No findings.".to_string());
        }

        Ok(Table::new(rows).to_string())
    }
}

/// Text formatter
pub struct TextFormatter;

impl OutputFormatter for TextFormatter {
    fn format(&self, results: &[AnalysisResult]) -> Result<String> {
        let mut output = String::new();

        for result in results {
            output.push_str(&format!("\n=== Certificate: {} ===\n", result.subject));
            output.push_str(&format!("Risk Score: {}/100\n", result.risk_score));
            output.push_str(&format!("Findings: {}\n\n", result.findings.len()));

            for finding in &result.findings {
                output.push_str(&format!("[{}] {}\n", finding.severity, finding.title));
                output.push_str(&format!("  {}\n", finding.description));
                if let Some(remediation) = &finding.remediation {
                    output.push_str(&format!("  Remediation: {remediation}\n"));
                }
                output.push('\n');
            }
        }

        Ok(output)
    }
}

/// Get formatter for the specified format
pub fn get_formatter(format: OutputFormat) -> Box<dyn OutputFormatter> {
    match format {
        OutputFormat::Json => Box::new(JsonFormatter),
        OutputFormat::Table => Box::new(TableFormatter),
        OutputFormat::Text => Box::new(TextFormatter),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{Finding, Severity};

    #[test]
    fn test_output_format_from_str() {
        assert_eq!("json".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert_eq!("table".parse::<OutputFormat>().unwrap(), OutputFormat::Table);
        assert_eq!("text".parse::<OutputFormat>().unwrap(), OutputFormat::Text);
        assert!("invalid".parse::<OutputFormat>().is_err());
    }

    #[test]
    fn test_json_formatter() {
        let results = vec![AnalysisResult {
            subject: "test.com".to_string(),
            findings: vec![Finding {
                severity: Severity::High,
                title: "Test Finding".to_string(),
                description: "Test description".to_string(),
                remediation: None,
            }],
            risk_score: 15,
        }];

        let formatter = JsonFormatter;
        let output = formatter.format(&results).unwrap();
        assert!(output.contains("test.com"));
        assert!(output.contains("Test Finding"));
    }
}
