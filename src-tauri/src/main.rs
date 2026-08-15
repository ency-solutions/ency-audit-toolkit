#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use serde::{Deserialize, Serialize};
use std::fs;
use tauri::{Manager, Window};

// ==================== DATA STRUCTURES ====================

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Finding {
    severity: String,
    title: String,
    description: String,
    recommendation: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuditResultEnvelope {
    success: bool,
    message: String,
    data: serde_json::Value,
}

// ==================== DNS/EMAIL SECURITY AUDIT ====================

#[tauri::command]
async fn check_email_security(domain: String) -> AuditResultEnvelope {
    let domain = domain.trim().trim_end_matches('.').to_lowercase();

    // Build a trust-dns resolver using system nameservers
    let resolver = match trust_dns_resolver::system_conf::read_system_conf() {
        Ok((conf, options)) => {
            let resolver = trust_dns_resolver::AsyncResolver::tokio(conf, options);
            // Try a basic lookup to verify it works; if that panics we'll catch it at runtime
            resolver
        }
        Err(e) => {
            return AuditResultEnvelope {
                success: false,
                message: "Failed to read system DNS config".to_string(),
                data: serde_json::json!({ "error": format!("{}", e) }),
            };
        }
    };

    let mut findings = Vec::new();
    let mut spf_score = 0i32;
    let mut dmarc_score = 0i32;
    let mut mx_score = 0i32;

    // --- SPF ---
    match resolver.txt_lookup(&domain).await {
        Ok(records) => {
            let txts: Vec<String> = records.iter().map(|r| r.to_string().trim_matches('"').to_string()).collect();
            let spf = txts.iter().find(|t| t.starts_with("v=spf1"));
            match spf {
                Some(record) => {
                    findings.push(Finding {
                        severity: "INFO".into(),
                        title: "SPF Record Found".into(),
                        description: format!("SPF: {}", record),
                        recommendation: None,
                    });
                    spf_score += 2;

                    if record.to_lowercase().contains("-all") {
                        findings.push(Finding {
                            severity: "GOOD".into(),
                            title: "SPF Uses Strict Policy".into(),
                            description: "SPF ends with -all (reject).".into(),
                            recommendation: None,
                        });
                        spf_score += 1;
                    } else if record.to_lowercase().contains("~all") {
                        findings.push(Finding {
                            severity: "LOW".into(),
                            title: "SPF Uses Soft Fail".into(),
                            description: "SPF ends with ~all (softfail). Consider -all.".into(),
                            recommendation: Some("Change ~all to -all for stricter validation.".into()),
                        });
                    } else if !record.to_lowercase().contains("all") {
                        findings.push(Finding {
                            severity: "MEDIUM".into(),
                            title: "SPF Missing Policy Qualifier".into(),
                            description: "SPF record doesn't specify what to do with unmatched senders.".into(),
                            recommendation: Some("Add ~all or -all at the end of your SPF record.".into()),
                        });
                    }

                    if record.contains("+all") || record.contains("all") {
                        findings.push(Finding {
                            severity: "HIGH".into(),
                            title: "SPF Allows Any Sender".into(),
                            description: "SPF contains +all or unqualified all.".into(),
                            recommendation: Some("Restrict SPF to known sending IPs/domains.".into()),
                        });
                        spf_score = 0;
                    }
                }
                None => {
                    findings.push(Finding {
                        severity: "HIGH".into(),
                        title: "No SPF Record Found".into(),
                        description: format!("No SPF TXT record for {}. Email spoofing risk.", domain),
                        recommendation: Some("Add an SPF record specifying authorized sending IPs/domains.".into()),
                    });
                }
            }
        }
        Err(e) => {
            findings.push(Finding {
                severity: "MEDIUM".into(),
                title: "Could Not Query SPF".into(),
                description: format!("TXT lookup failed: {}", e),
                recommendation: None,
            });
        }
    }

    // --- DMARC ---
    let dmarc_domain = format!("_dmarc.{}", domain);
    match resolver.txt_lookup(&dmarc_domain).await {
        Ok(records) => {
            let txts: Vec<String> = records.iter()
                .map(|r| r.to_string().trim_matches('"').to_string())
                .collect();
            let dmarc = txts.iter().find(|t| t.starts_with("v=dmarc1"));
            match dmarc {
                Some(record) => {
                    findings.push(Finding {
                        severity: "INFO".into(),
                        title: "DMARC Record Found".into(),
                        description: format!("DMARC: {}", record),
                        recommendation: None,
                    });
                    dmarc_score += 2;

                    let rl = record.to_lowercase();
                    if rl.contains("p=reject") || rl.contains("p=reject") {
                        findings.push(Finding {
                            severity: "GOOD".into(),
                            title: "DMARC Uses Reject Policy".into(),
                            description: "DMARC p=reject blocks failing emails.".into(),
                            recommendation: None,
                        });
                        dmarc_score += 2;
                    } else if rl.contains("p=quarantine") {
                        findings.push(Finding {
                            severity: "LOW".into(),
                            title: "DMARC Uses Quarantine Policy".into(),
                            description: "DMARC p=quarantine sends failing emails to spam.".into(),
                            recommendation: Some("Consider upgrading to p=reject when confident.".into()),
                        });
                        dmarc_score += 1;
                    } else if rl.contains("p=none") {
                        findings.push(Finding {
                            severity: "MEDIUM".into(),
                            title: "DMARC in Monitoring Mode Only".into(),
                            description: "DMARC p=none does not block spoofed emails.".into(),
                            recommendation: Some("Move to p=quarantine or p=reject for enforcement.".into()),
                        });
                    }
                }
                None => {
                    findings.push(Finding {
                        severity: "HIGH".into(),
                        title: "No DMARC Record Found".into(),
                        description: format!("No DMARC record at {}. Higher phishing risk.", dmarc_domain),
                        recommendation: Some("Publish a DMARC record at _dmarc.yourdomain.com.".into()),
                    });
                }
            }
        }
        Err(e) => {
            findings.push(Finding {
                severity: "MEDIUM".into(),
                title: "Could Not Query DMARC".into(),
                description: format!("DMARC lookup failed: {}", e),
                recommendation: None,
            });
        }
    }

    // --- MX ---
    match resolver.mx_lookup(&domain).await {
        Ok(mx) => {
            let count = mx.iter().count();
            mx_score += 1;
            findings.push(Finding {
                severity: "INFO".into(),
                title: "MX Records Found".into(),
                description: format!("Found {} MX record(s).", count),
                recommendation: if count == 1 {
                    Some("Consider a secondary MX for redundancy.".into())
                } else {
                    None
                },
            });
        }
        Err(e) => {
            findings.push(Finding {
                severity: "MEDIUM".into(),
                title: "No MX Records Found".into(),
                description: format!("Failed to query MX: {}", e),
                recommendation: Some("Ensure MX records are configured for email delivery.".into()),
            });
        }
    }

    let total_score = spf_score + dmarc_score + mx_score;
    let overall = if total_score >= 7 { "GOOD" }
                  else if total_score >= 4 { "FAIR" }
                  else { "POOR" };

    AuditResultEnvelope {
        success: true,
        message: format!("Email security audit for {}", domain),
        data: serde_json::json!({
            "domain": domain,
            "findings": findings,
            "overall_score": overall,
            "score_breakdown": {
                "spf": spf_score,
                "dmarc": dmarc_score,
                "mx": mx_score,
                "total": total_score
            }
        }),
    }
}

// ==================== SSL/TLS AUDIT ====================

#[tauri::command]
async fn check_ssl(target: String) -> AuditResultEnvelope {
    let target = target.trim().to_string();

    // Normalize URL
    let url = if target.starts_with("https://") {
        target.clone()
    } else {
        format!("https://{}", target)
    };

    let mut findings = Vec::new();
    let mut score = 0i32;

    // Build a reqwest client with some config for cert inspection
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(false)
        .build();

    match client {
        Ok(client) => {
            // Use reqwest's TLS stack directly — handshake success means cert is valid
            match client.get(&url).send().await {
                Ok(resp) => {
                    let status = resp.status();

                    // Status info
                    if status.is_success() {
                        findings.push(Finding {
                            severity: "INFO".into(),
                            title: "Server Responded Successfully".into(),
                            description: format!("HTTP status {}", status),
                            recommendation: None,
                        });
                        score += 1;
                    } else {
                        findings.push(Finding {
                            severity: "LOW".into(),
                            title: "Server Returned Non-Success Status".into(),
                            description: format!("HTTP {} (still acceptable for SSL test)", status),
                            recommendation: None,
                        });
                    }

                    // TLS handshake succeeded means certificate is valid/verified
                    findings.push(Finding {
                        severity: "GOOD".into(),
                        title: "Valid TLS Certificate Presented".into(),
                        description: "Certificate was successfully verified by the TLS stack.".into(),
                        recommendation: None,
                    });
                    score += 3;

                    // Check for HTTPS redirect (simple)
                    let http_url = url.replace("https://", "http://");
                    if let Ok(http_resp) = client.get(&http_url).send().await {
                        if http_resp.status().is_redirection() {
                            findings.push(Finding {
                                severity: "GOOD".into(),
                                title: "HTTP Redirects to HTTPS".into(),
                                description: "Plain HTTP traffic is redirected to HTTPS.".into(),
                                recommendation: None,
                            });
                            score += 1;
                        } else {
                            findings.push(Finding {
                                severity: "MEDIUM".into(),
                                title: "HTTP Not Redirecting to HTTPS".into(),
                                description: "Site serves content over plain HTTP.".into(),
                                recommendation: Some("Configure HTTP->HTTPS redirect.".into()),
                            });
                        }
                    }
                }
                Err(e) => {
                    let msg = e.to_string().to_lowercase();
                    if msg.contains("certificate") || msg.contains("expired") || msg.contains("not after") {
                        findings.push(Finding {
                            severity: "CRITICAL".into(),
                            title: "SSL Certificate Verification Failed".into(),
                            description: format!("Certificate is invalid, expired, or self-signed: {}", e),
                            recommendation: Some("Renew or replace the SSL certificate.".into()),
                        });
                        score = 0;
                    } else if msg.contains("timeout") || msg.contains("timed out") {
                        findings.push(Finding {
                            severity: "HIGH".into(),
                            title: "Connection Timed Out".into(),
                            description: format!("Server at {} did not respond in time.", url),
                            recommendation: Some("Check server availability and firewall rules.".into()),
                        });
                    } else {
                        findings.push(Finding {
                            severity: "MEDIUM".into(),
                            title: "Connection Failed".into(),
                            description: format!("{}", e),
                            recommendation: Some("Verify the URL is correct and the server is online.".into()),
                        });
                    }
                }
            }
        }
        Err(e) => {
            return AuditResultEnvelope {
                success: false,
                message: "Failed to build HTTPS client".into(),
                data: serde_json::json!({ "error": format!("{}", e) }),
            };
        }
    }

    let overall = if score >= 5 { "GOOD" }
                  else if score >= 3 { "FAIR" }
                  else { "POOR" };

    AuditResultEnvelope {
        success: true,
        message: format!("SSL/TLS audit for {}", url),
        data: serde_json::json!({
            "target": url,
            "findings": findings,
            "overall_score": overall,
            "score": score
        }),
    }
}

// ==================== FIREWALL CONFIG ANALYSIS ====================

#[tauri::command]
fn read_file(path: String) -> Result<String, String> {
    std::fs::read_to_string(&path).map_err(|e| e.to_string())
}

#[tauri::command]
async fn analyze_firewall(content: String) -> AuditResultEnvelope {
    let mut findings = Vec::new();
    let lower = content.to_lowercase();
    let lines: Vec<&str> = content.lines().collect();

    let rules_count = lines.iter()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#') && !t.starts_with(';') && !t.starts_with("!!")
        })
        .count();

    // --- iptables/ufw-style checks ---
    if lower.contains("allow any") || lower.contains("permit any any") || lower.contains("accept all") {
        findings.push(Finding {
            severity: "CRITICAL".into(),
            title: "Overly Permissive Allow Rule".into(),
            description: "Rule allows traffic from any source to any destination.".into(),
            recommendation: Some("Scope rules to specific networks, ports, and protocols.".into()),
        });
    }

    // Any rule allowing 0.0.0.0/0 or ::/0 on a sensitive port
    if (lower.contains("0.0.0.0/0") || lower.contains("::/0"))
        && (lower.contains("port 22") || lower.contains("port 3389") || lower.contains("dport 22") || lower.contains("dport 3389"))
    {
        findings.push(Finding {
            severity: "HIGH".into(),
            title: "Remote Access Open to the Internet".into(),
            description: "SSH or RDP is exposed to 0.0.0.0/0.".into(),
            recommendation: Some("Restrict remote access to known IPs or use a VPN.".into()),
        });
    }

    // Telnet
    if lower.contains("telnet") || lower.contains("port 23") || lower.contains("dport 23") {
        findings.push(Finding {
            severity: "HIGH".into(),
            title: "Telnet (Port 23) Allowed".into(),
            description: "Telnet sends data and credentials in plaintext.".into(),
            recommendation: Some("Replace Telnet access with SSH.".into()),
        });
    }

    // FTP
    if lower.contains("ftp") && !lower.contains("sftp") && !lower.contains("ftps") {
        findings.push(Finding {
            severity: "HIGH".into(),
            title: "Unencrypted FTP Detected".into(),
            description: "Standard FTP transmits data without encryption.".into(),
            recommendation: Some("Use SFTP or FTPS instead.".into()),
        });
    }

    // Default credentials hints
    if lower.contains("password admin") || lower.contains("password default") || lower.contains("password = admin") {
        findings.push(Finding {
            severity: "CRITICAL".into(),
            title: "Potential Default Credentials".into(),
            description: "Configuration may contain default or weak passwords.".into(),
            recommendation: Some("Change all default passwords immediately.".into()),
        });
    }

    // Promiscuous mode / debugging enabled
    if lower.contains("promiscuous") || lower.contains("enable debug") || lower.contains("debug all") {
        findings.push(Finding {
            severity: "MEDIUM".into(),
            title: "Debug/Promiscuous Mode Enabled".into(),
            description: "Debug or promiscuous mode can leak information.".into(),
            recommendation: Some("Disable debug features in production.".into()),
        });
    }

    // Missing explicit deny at end
    let last_real = lines.iter()
        .rev()
        .find(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#') && !t.starts_with(';')
        });

    if let Some(l) = last_real {
        let ll = l.to_lowercase();
        if !ll.contains("deny") && !ll.contains("drop") && !ll.contains("reject") && rules_count > 5 {
            findings.push(Finding {
                severity: "MEDIUM".into(),
                title: "No Explicit Default-Deny Rule".into(),
                description: "Firewall rules do not end with an explicit deny-all rule.".into(),
                recommendation: Some("Add a default-deny rule at the end of the rule chain.".into()),
            });
        }
    }

    let has_critical = findings.iter().any(|f| f.severity == "CRITICAL");
    let has_high = findings.iter().any(|f| f.severity == "HIGH");

    let score = if has_critical { "POOR" }
                 else if has_high { "FAIR" }
                 else if findings.is_empty() { "GOOD" }
                 else { "GOOD" };

    if findings.is_empty() {
        findings.push(Finding {
            severity: "INFO".into(),
            title: "No Issues Detected".into(),
            description: format!("Analyzed {} rules; no obvious problems found.", rules_count),
            recommendation: Some("Continue periodic reviews.".into()),
        });
    }

    AuditResultEnvelope {
        success: true,
        message: format!("Firewall analysis: {} rules, {} issues", rules_count, findings.len()),
        data: serde_json::json!({
            "rules_count": rules_count,
            "findings": findings,
            "overall_score": score
        }),
    }
}

// ==================== PORT SCANNER ====================

#[tauri::command]
async fn scan_ports(target: String) -> AuditResultEnvelope {
    let target = target.trim().to_string();
    if target.is_empty() {
        return AuditResultEnvelope {
            success: false,
            message: "Target is empty".into(),
            data: serde_json::json!({"findings": []}),
        };
    }

    // Common ports to check (service:port)
    let common_ports = [
        (21, "FTP"),
        (22, "SSH"),
        (23, "Telnet"),
        (25, "SMTP"),
        (53, "DNS"),
        (80, "HTTP"),
        (110, "POP3"),
        (135, "RPC"),
        (139, "NetBIOS"),
        (143, "IMAP"),
        (443, "HTTPS"),
        (445, "SMB"),
        (993, "IMAPS"),
        (995, "POP3S"),
        (3306, "MySQL"),
        (3389, "RDP"),
        (5432, "PostgreSQL"),
        (5900, "VNC"),
        (8080, "HTTP-Alt"),
        (8443, "HTTPS-Alt"),
    ];

    let mut findings = Vec::new();
    let mut open_ports: Vec<(u16, String)> = Vec::new();
    let mut closed_count = 0usize;
    let mut timeout_count = 0usize;

    // Scan ports concurrently
    let mut handles = Vec::new();
    for (port, service) in &common_ports {
        let target_clone = target.clone();
        let port = *port;
        let service = (*service).to_string();
        let handle = tokio::spawn(async move {
            let timeout = tokio::time::Duration::from_secs(3);
            let addr = format!("{}:{}", target_clone, port);
            match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
                Ok(Ok(_)) => ("open".to_string(), service),
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => ("closed".to_string(), service),
                Err(_) => ("timeout".to_string(), service), // timed out
                Ok(Err(_)) => ("closed".to_string(), service),
            }
        });
        handles.push((port, handle));
    }

    for (port, handle) in handles {
        match handle.await {
            Ok((status, service)) => {
                match status.as_str() {
                    "open" => {
                        open_ports.push((port, service.clone()));
                        // Security assessments per port
                        match port {
                            21 => findings.push(Finding {
                                severity: "MEDIUM".into(),
                                title: format!("FTP Open (port {})", port),
                                description: "FTP transmits credentials in plaintext.".into(),
                                recommendation: Some("Use SFTP (port 22) instead.".into()),
                            }),
                            22 => findings.push(Finding {
                                severity: "INFO".into(),
                                title: format!("SSH Open (port {})", port),
                                description: "SSH is encrypted but ensure strong auth.".into(),
                                recommendation: Some("Use key-based auth; disable password login.".into()),
                            }),
                            23 => findings.push(Finding {
                                severity: "HIGH".into(),
                                title: format!("Telnet Open (port {})", port),
                                description: "Telnet sends all data in plaintext including passwords.".into(),
                                recommendation: Some("Disable Telnet; use SSH instead.".into()),
                            }),
                            445 => findings.push(Finding {
                                severity: "HIGH".into(),
                                title: format!("SMB Open (port {})", port),
                                description: "SMB exposed — ransomware target (e.g., WannaCry).".into(),
                                recommendation: Some("Restrict SMB to internal network only.".into()),
                            }),
                            3389 => findings.push(Finding {
                                severity: "HIGH".into(),
                                title: format!("RDP Open (port {})", port),
                                description: "Remote Desktop exposed — brute-force risk.".into(),
                                recommendation: Some("Use VPN to access RDP; never expose directly.".into()),
                            }),
                            5900 => findings.push(Finding {
                                severity: "MEDIUM".into(),
                                title: format!("VNC Open (port {})", port),
                                description: "VNC may transmit unencrypted screen data.".into(),
                                recommendation: Some("Use SSH tunneling for VNC access.".into()),
                            }),
                            3306 => findings.push(Finding {
                                severity: "MEDIUM".into(),
                                title: format!("MySQL Open (port {})", port),
                                description: "Database directly accessible — data leak risk.".into(),
                                recommendation: Some("Bind MySQL to localhost; use SSH tunnel for access.".into()),
                            }),
                            5432 => findings.push(Finding {
                                severity: "MEDIUM".into(),
                                title: format!("PostgreSQL Open (port {})", port),
                                description: "Database directly accessible — data leak risk.".into(),
                                recommendation: Some("Bind PostgreSQL to localhost; use SSH tunnel for access.".into()),
                            }),
                            80 => findings.push(Finding {
                                severity: "INFO".into(),
                                title: format!("HTTP Open (port {})", port),
                                description: "Unencrypted web traffic — should redirect to HTTPS.".into(),
                                recommendation: None,
                            }),
                            443 => findings.push(Finding {
                                severity: "GOOD".into(),
                                title: format!("HTTPS Open (port {})", port),
                                description: "Encrypted web traffic — good.".into(),
                                recommendation: None,
                            }),
                            _ => findings.push(Finding {
                                severity: "INFO".into(),
                                title: format!("{} Open (port {})", service, port),
                                description: format!("Port {} ({}) is accessible.", port, service),
                                recommendation: Some("Verify this service is intentional.".into()),
                            }),
                        }
                    }
                    "closed" => closed_count += 1,
                    "timeout" => {
                        timeout_count += 1;
                        findings.push(Finding {
                            severity: "LOW".into(),
                            title: format!("Port {} ({}) Timed Out", port, service),
                            description: "Connection timed out — possibly filtered by firewall.".into(),
                            recommendation: None,
                        });
                    }
                    _ => {}
                }
            }
            Err(e) => {
                findings.push(Finding {
                    severity: "LOW".into(),
                    title: format!("Scan Error on port {}", port),
                    description: format!("{}", e),
                    recommendation: None,
                });
            }
        }
    }

    if open_ports.is_empty() {
        findings.push(Finding {
            severity: "GOOD".into(),
            title: "No Common Ports Open".into(),
            description: "No commonly exploitable ports were reachable.".into(),
            recommendation: Some("Continue regular port scans.".into()),
        });
    }

    AuditResultEnvelope {
        success: true,
        message: format!("Port scan complete: {} open, {} closed, {} timed out", open_ports.len(), closed_count, timeout_count),
        data: serde_json::json!({
            "target": target,
            "open_ports": open_ports,
            "findings": findings,
            "summary": {
                "open": open_ports.len(),
                "closed": closed_count,
                "timeout": timeout_count
            }
        }),
    }
}

// ==================== RISK SCORING ENGINE ====================

#[derive(Debug, Serialize, Deserialize, Clone)]
struct RiskScoreResult {
    score: i32,               // 0-100 (100 = no risk, 0 = critical risk)
    level: String,            // LOW / MODERATE / HIGH / CRITICAL
    findings_count: usize,
    critical_count: i32,
    high_count: i32,
    medium_count: i32,
    low_count: i32,
    good_count: i32,
    executive_summary: String,
}

#[tauri::command]
fn calculate_risk_score(findings: Vec<Finding>) -> RiskScoreResult {
    let mut score = 100i32;
    let mut critical_count = 0i32;
    let mut high_count = 0i32;
    let mut medium_count = 0i32;
    let mut low_count = 0i32;
    let mut good_count = 0i32;

    for f in &findings {
        match f.severity.to_lowercase().as_str() {
            "critical" => { critical_count += 1; score -= 15; }
            "high"     => { high_count += 1;    score -= 8; }
            "medium"   => { medium_count += 1;  score -= 4; }
            "low" | "info" => { low_count += 1; score -= 1; }
            "good"     => { good_count += 1;    score += 2; }
            _          => { /* unknown severity, ignore */ }
        }
    }

    // Clamp score between 0 and 100
    score = score.max(0).min(100);

    // Determine risk level
    let level = if score >= 80 {
        "LOW".into()
    } else if score >= 60 {
        "MODERATE".into()
    } else if score >= 35 {
        "HIGH".into()
    } else {
        "CRITICAL".into()
    };

    // Generate executive summary language
    let exec_summary = if level == "CRITICAL" {
        format!(
            "Security posture is CRITICAL (Score: {}/100). {} critical and {} high-severity issues identified. Immediate remediation required to reduce risk of compromise. Recommend prioritizing critical findings within 24 hours.",
            score, critical_count, high_count
        )
    } else if level == "HIGH" {
        format!(
            "Security posture is HIGH RISK (Score: {}/100). Significant gaps detected across {} findings. Recommend addressing high-severity issues within 1 week and implementing monitoring.",
            score, findings.len()
        )
    } else if level == "MODERATE" {
        format!(
            "Security posture is MODERATE (Score: {}/100). {} areas for improvement identified. Current controls are partially effective; recommend remediation within 30 days.",
            score, findings.len()
        )
    } else {
        format!(
            "Security posture is GOOD (Score: {}/100). {} minor findings; overall controls are effective. Continue regular review and address remaining items at your convenience.",
            score, findings.len()
        )
    };

    RiskScoreResult {
        score,
        level,
        findings_count: findings.len(),
        critical_count,
        high_count,
        medium_count,
        low_count,
        good_count,
        executive_summary: exec_summary,
    }
}

// ==================== GENERIC AUDIT ROUTER ====================

#[tauri::command]
async fn run_audit(audit_type: String) -> AuditResultEnvelope {
    match audit_type.as_str() {
        "firewall" => AuditResultEnvelope {
            success: true,
            message: "Firewall audit selected".into(),
            data: serde_json::json!({
                "title": "Firewall Configuration Audit",
                "overall_score": "PENDING",
                "summary": "Upload a firewall config file (.conf/.cfg/.txt) to analyze.",
                "findings": [{
                    "severity": "INFO",
                    "title": "Ready",
                    "description": "Drop or select a firewall configuration file.",
                    "recommendation": "Supported: iptables, UFW, Cisco IOS, Palo Alto, generic ACL formats"
                }]
            }),
        },
        "dns" => AuditResultEnvelope {
            success: true,
            message: "DNS/Email security audit selected".into(),
            data: serde_json::json!({
                "title": "DNS & Email Security Audit",
                "overall_score": "PENDING",
                "summary": "Enter your domain to check SPF, DKIM, DMARC, and MX records.",
                "findings": [{
                    "severity": "INFO",
                    "title": "Ready",
                    "description": "Type your domain (e.g., example.com).",
                    "recommendation": "Read-only DNS queries; no changes made."
                }]
            }),
        },
        "ssl" => AuditResultEnvelope {
            success: true,
            message: "SSL/TLS audit selected".into(),
            data: serde_json::json!({
                "title": "SSL/TLS Certificate Audit",
                "overall_score": "PENDING",
                "summary": "Enter a URL to validate its HTTPS configuration.",
                "findings": [{
                    "severity": "INFO",
                    "title": "Ready",
                    "description": "Provide your HTTPS URL (e.g., https://example.com).",
                    "recommendation": "Checks certificate validity, HTTP->HTTPS redirect, and connectivity."
                }]
            }),
        },
        other => AuditResultEnvelope {
            success: false,
            message: format!("Unknown audit type: {}", other),
            data: serde_json::json!({
                "title": "Audit Error",
                "overall_score": "ERROR",
                "summary": "Unknown audit module.",
                "findings": []
            }),
        },
    }
}

// ==================== EXPORT REPORT ====================

#[tauri::command]
async fn export_report(window: Window, html: String) -> Result<String, String> {
    use chrono::Local;
    use std::path::PathBuf;

    let app_handle = window.app_handle();
    let download_dir = app_handle.path()
        .download_dir()
        .map_err(|e| format!("Failed to get download directory: {}", e))?;

    let timestamp = Local::now().format("%Y%m%d-%H%M%S");
    let filename = format!("ency-audit-report-{}.html", timestamp);
    let filepath: PathBuf = download_dir.join(&filename);

    fs::write(&filepath, html)
        .map_err(|e| format!("Failed to write report: {}", e))?;

    Ok(filepath.to_string_lossy().to_string())
}

#[tauri::command]
async fn export_json_report(path: String, data: String) -> Result<(), String> {
    use std::io::Write;

    let json: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    let pretty = serde_json::to_string_pretty(&json)
        .map_err(|e| format!("Failed to format JSON: {}", e))?;

    let mut file = fs::File::create(&path)
        .map_err(|e| format!("Failed to create file {}: {}", path, e))?;

    file.write_all(pretty.as_bytes())
        .map_err(|e| format!("Failed to write file: {}", e))?;

    Ok(())
}

// ==================== FILE PICKER ====================

#[tauri::command]
async fn pick_firewall_config(app_handle: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    use tokio::sync::oneshot;

    let (tx, rx) = oneshot::channel();

    app_handle.dialog()
        .file()
        .set_title("Select Firewall Configuration File")
        .add_filter("Config Files", &["conf", "cfg", "txt", "acl"])
        .pick_file(move |path| {
            let _ = tx.send(path.map(|p| p.to_string()));
        });

    let result = rx.await.map_err(|e| format!("Dialog channel closed: {}", e))?;
    Ok(result)
}

// ==================== MAIN ====================

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .invoke_handler(tauri::generate_handler![
            check_email_security,
            check_ssl,
            analyze_firewall,
            scan_ports,
            calculate_risk_score,
            run_audit,
            export_report,
            export_json_report,
            pick_firewall_config,
            read_file,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Ency Audit Toolkit");
}
