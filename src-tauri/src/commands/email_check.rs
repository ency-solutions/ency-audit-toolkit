use crate::error::AppResult;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailSecurityReport {
    pub domain: String,
    pub score: u8,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub check: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAuditInput {
    pub domain: String,
}

pub async fn check_email_security(domain: String) -> AppResult<EmailSecurityReport> {
    let domain = domain.to_lowercase().trim().to_string();
    let mut findings = Vec::new();
    let mut score = 100u8;

    if domain.is_empty() {
        return Ok(EmailSecurityReport {
            domain: "unknown".to_string(),
            score: 0,
            findings: vec![Finding {
                check: "Input Validation".to_string(),
                status: "FAIL".to_string(),
                detail: "No domain provided for audit".to_string(),
            }],
        });
    }

    // SPF Record Check
    let spf_result = trust_dns_resolver::system_conf::read_system_conf()
        .map(|(cfg, opts)| {
            trust_dns_resolver::TokioAsyncResolver::tokio(cfg, opts)
        })
        .and_then(|mut resolver| {
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                resolver.txt_lookup(&domain.parse().unwrap()),
            )
        });

    match spf_result {
        Ok(res) => {
            let records: Vec<String> = res
                .iter()
                .map(|r| r.to_string())
                .collect();
            let spf_text = records.join(" ");
            if spf_text.contains("v=spf1") {
                let strictness = if spf_text.contains("-all") {
                    "Strict (Fail)"
                } else if spf_text.contains("~all") {
                    "Soft (Softfail)"
                } else if spf_text.contains("+all") {
                    "Permissive"
                } else {
                    "No mechanism specified"
                };
                findings.push(Finding {
                    check: "SPF Record".to_string(),
                    status: "PASS".to_string(),
                    detail: format!("Found SPF record ({})\nRecord: {}", strictness, spf_text),
                });
            } else {
                score -= 25;
                findings.push(Finding {
                    check: "SPF Record".to_string(),
                    status: "FAIL".to_string(),
                    detail: "SPF record exists but missing 'v=spf1' tag".to_string(),
                });
            }
        }
        Err(_) => {
            score -= 25;
            findings.push(Finding {
                check: "SPF Record".to_string(),
                status: "FAIL".to_string(),
                detail: "No SPF record found for this domain".to_string(),
            });
        }
    }

    // DKIM Check (info only)
    findings.push(Finding {
        check: "DKIM".to_string(),
        status: "INFO".to_string(),
        detail: "DKIM requires public key verification against received headers. Check DMARC reports for DKIM signing status.".to_string(),
    });

    // DMARC Check
    let dmarc_result = trust_dns_resolver::system_conf::read_system_conf()
        .map(|(cfg, opts)| {
            trust_dns_resolver::TokioAsyncResolver::tokio(cfg, opts)
        })
        .and_then(|mut resolver| {
            let dmarc_domain = format!("_dmarc.{}", domain);
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                resolver.txt_lookup(&dmarc_domain.parse().unwrap()),
            )
        });

    match dmarc_result {
        Ok(res) => {
            let records: Vec<String> = res
                .iter()
                .map(|r| r.to_string())
                .collect();
            let dmarc_text = records.join(" ");
            let policy = if dmarc_text.contains("p=reject") {
                "Reject"
            } else if dmarc_text.contains("p=quarantine") {
                "Quarantine"
            } else if dmarc_text.contains("p=none") {
                "None (Monitoring)"
            } else {
                "Unknown"
            };
            if policy == "Reject" || policy == "Quarantine" {
                findings.push(Finding {
                    check: "DMARC".to_string(),
                    status: "PASS".to_string(),
                    detail: format!("DMARC record found (Policy: {})\nRecord: {}", policy, dmarc_text),
                });
            } else {
                score -= 10;
                findings.push(Finding {
                    check: "DMARC".to_string(),
                    status: "WARN".to_string(),
                    detail: format!("DMARC record found but policy is '{}'. Recommend 'quarantine' or 'reject'.\nRecord: {}", policy, dmarc_text),
                });
            }
        }
        Err(_) => {
            score -= 25;
            findings.push(Finding {
                check: "DMARC".to_string(),
                status: "FAIL".to_string(),
                detail: "No DMARC record found for this domain".to_string(),
            });
        }
    }

    // Basic MX Record Check
    let mx_result = trust_dns_resolver::system_conf::read_system_conf()
        .map(|(cfg, opts)| {
            trust_dns_resolver::TokioAsyncResolver::tokio(cfg, opts)
        })
        .and_then(|mut resolver| {
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                resolver.mx_lookup(&domain.parse().unwrap()),
            )
        });

    match mx_result {
        Ok(res) => {
            let mx_servers: Vec<String> = res.iter().map(|m| m.exchange().to_string()).collect();
            findings.push(Finding {
                check: "MX Records".to_string(),
                status: "PASS".to_string(),
                detail: format!("Mail exchange records found: {}", mx_servers.join(", ")),
            });
        }
        Err(_) => {
            findings.push(Finding {
                check: "MX Records".to_string(),
                status: "WARN".to_string(),
                detail: "No MX records found. Domain may not accept email directly.".to_string(),
            });
        }
    }

    // DNSSEC Check (basic)
    findings.push(Finding {
        check: "DNSSEC".to_string(),
        status: "INFO".to_string(),
        detail: format!("DNSSEC validation requires a validating resolver. Verify {} uses DNSSEC via a DNSSEC-aware tool.", domain),
    });

    Ok(EmailSecurityReport {
        domain,
        score: score.max(0),
        findings,
    })
}
