use crate::error::AppResult;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallAuditReport {
    pub file: String,
    pub rules_analyzed: usize,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub check: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallAuditInput {
    pub file_path: String,
}

pub async fn analyze_firewall(file_path: String) -> AppResult<FirewallAuditReport> {
    let content = fs::read_to_string(&file_path).map_err(|e| {
        anyhow::anyhow!("Failed to read firewall config file: {}", e)
    })?;

    let mut rules_analyzed = 0;
    let mut findings = Vec::new();
    let mut has_default_deny = false;
    let mut has_ssh_open = false;
    let mut has_telnet = false;
    let mut has_unrestricted_ingress = false;
    let mut has_logging = false;
    let mut lines = content.lines().peekable();

    // Parse iptables/nftables-style rules
    while let Some(line) = lines.next() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        rules_analyzed += 1;

        let lower = line.to_lowercase();

        // Check for default DROP/DENY policies
        if lower.contains("default") && (lower.contains("drop") || lower.contains("deny")) {
            has_default_deny = true;
        }

        // Check for open SSH (port 22) from any source
        if (lower.contains("22") || lower.contains("ssh"))
            && (lower.contains("accept") || lower.contains("allow"))
            && (lower.contains("any") || lower.contains("0.0.0.0/0") || lower.contains("::/0"))
        {
            has_ssh_open = true;
        }

        // Check for telnet (port 23) usage
        if lower.contains("23") || lower.contains("telnet") {
            has_telnet = true;
        }

        // Check for unrestricted ingress
        if (lower.contains("accept") || lower.contains("allow") || lower.contains("inbound"))
            && (lower.contains("any") || lower.contains("0.0.0.0/0") || lower.contains("all"))
            && (lower.contains("input") || lower.contains("ingress") || lower.contains("from any"))
        {
            has_unrestricted_ingress = true;
        }

        // Check for logging rules
        if lower.contains("log") || lower.contains("audit") || lower.contains("record") {
            has_logging = true;
        }
    }

    // Generate findings
    if has_default_deny {
        findings.push(Finding {
            check: "Default Deny Policy".to_string(),
            status: "PASS".to_string(),
            detail: "Firewall uses a default deny/drop policy for unmatched traffic".to_string(),
        });
    } else {
        findings.push(Finding {
            check: "Default Deny Policy".to_string(),
            status: "FAIL".to_string(),
            detail: "No default deny policy detected. All unmatched traffic may be allowed by default.".to_string(),
        });
    }

    if has_ssh_open {
        findings.push(Finding {
            check: "SSH Access".to_string(),
            status: "WARN".to_string(),
            detail: "SSH (port 22) appears open to all sources. Restrict to known IPs or use a bastion host.".to_string(),
        });
    } else {
        findings.push(Finding {
            check: "SSH Access".to_string(),
            status: "PASS".to_string(),
            detail: "SSH access appears restricted to specific sources.".to_string(),
        });
    }

    if has_telnet {
        findings.push(Finding {
            check: "Telnet Usage".to_string(),
            status: "FAIL".to_string(),
            detail: "Telnet (port 23) detected. Telnet transmits credentials in plaintext. Use SSH instead.".to_string(),
        });
    } else {
        findings.push(Finding {
            check: "Telnet Usage".to_string(),
            status: "PASS".to_string(),
            detail: "No telnet usage detected in firewall rules.".to_string(),
        });
    }

    if has_unrestricted_ingress {
        findings.push(Finding {
            check: "Ingress Restrictions".to_string(),
            status: "WARN".to_string(),
            detail: "Unrestricted ingress rules detected. Only allow necessary ports and sources.".to_string(),
        });
    } else {
        findings.push(Finding {
            check: "Ingress Restrictions".to_string(),
            status: "PASS".to_string(),
            detail: "No unrestricted ingress rules detected.".to_string(),
        });
    }

    if has_logging {
        findings.push(Finding {
            check: "Logging Enabled".to_string(),
            status: "PASS".to_string(),
            detail: "Firewall logging appears enabled. Ensure logs are centralized and monitored.".to_string(),
        });
    } else {
        findings.push(Finding {
            check: "Logging Enabled".to_string(),
            status: "WARN".to_string(),
            detail: "No explicit logging rules found. Enable logging for denied traffic and anomalies.".to_string(),
        });
    }

    // Summary check
    findings.push(Finding {
        check: "Configuration Summary".to_string(),
        status: "INFO".to_string(),
        detail: format!(
            "Analyzed {} lines from {}. This is a basic heuristic scan—manual review recommended.",
            rules_analyzed, file_path
        ),
    });

    Ok(FirewallAuditReport {
        file: file_path,
        rules_analyzed,
        findings,
    })
}
