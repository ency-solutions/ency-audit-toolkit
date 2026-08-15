use crate::error::AppResult;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslAuditReport {
    pub host: String,
    pub port: u16,
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
pub struct SslAuditInput {
    pub host: String,
    pub port: Option<u16>,
}

pub async fn check_ssl_certificate(host: String, port: Option<u16>) -> AppResult<SslAuditReport> {
    let port = port.unwrap_or(443);
    let url = format!("https://{}:{}", host, port);
    let mut findings = Vec::new();
    let mut score = 100u8;

    if host.is_empty() {
        return Ok(SslAuditReport {
            host: "unknown".to_string(),
            port,
            score: 0,
            findings: vec![Finding {
                check: "Input Validation".to_string(),
                status: "FAIL".to_string(),
                detail: "No host provided for audit".to_string(),
            }],
        });
    }

    // Attempt TLS connection
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(false)
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP client: {}", e))?;

    let response = client.get(&url).send().await;

    match response {
        Ok(resp) => {
            let status = resp.status();
            findings.push(Finding {
                check: "TLS Connection".to_string(),
                status: "PASS".to_string(),
                detail: format!("Successfully established TLS connection. HTTP status: {}", status),
            });

            // Get certificate info
            if let Ok(certs) = resp.urls().last().map(|_| ()) {
                let _ = certs; // reqwest doesn't expose cert details easily without extra crates
            }

            // Check for common security headers (from response)
            let headers = resp.headers();

            // HSTS
            if headers.get("strict-transport-security").is_some() {
                findings.push(Finding {
                    check: "HSTS".to_string(),
                    status: "PASS".to_string(),
                    detail: "Strict-Transport-Security header is present".to_string(),
                });
            } else {
                score -= 10;
                findings.push(Finding {
                    check: "HSTS".to_string(),
                    status: "WARN".to_string(),
                    detail: "Missing Strict-Transport-Security header. Recommend adding HSTS with max-age >= 31536000".to_string(),
                });
            }

            // X-Content-Type-Options
            if headers.get("x-content-type-options").map_or(false, |v| v.to_str().unwrap_or("") == "nosniff") {
                findings.push(Finding {
                    check: "X-Content-Type-Options".to_string(),
                    status: "PASS".to_string(),
                    detail: "X-Content-Type-Options: nosniff is set".to_string(),
                });
            } else {
                findings.push(Finding {
                    check: "X-Content-Type-Options".to_string(),
                    status: "INFO".to_string(),
                    detail: "X-Content-Type-Options header not set or not 'nosniff'".to_string(),
                });
            }

            // X-Frame-Options
            if headers.get("x-frame-options").is_some() || headers.get("content-security-policy").map_or(false, |v| v.to_str().unwrap_or("").contains("frame")) {
                findings.push(Finding {
                    check: "Clickjacking Protection".to_string(),
                    status: "PASS".to_string(),
                    detail: "Frame restriction headers detected (X-Frame-Options or CSP frame-src)".to_string(),
                });
            } else {
                score -= 5;
                findings.push(Finding {
                    check: "Clickjacking Protection".to_string(),
                    status: "WARN".to_string(),
                    detail: "No clickjacking protection headers detected".to_string(),
                });
            }
        }
        Err(e) => {
            score -= 40;
            let err_msg = e.to_string();
            if err_msg.contains("certificate") || err_msg.contains("ssl") || err_msg.contains("tls") {
                findings.push(Finding {
                    check: "TLS Connection".to_string(),
                    status: "FAIL".to_string(),
                    detail: format!("Certificate error: {}. Certificate may be expired, self-signed, or misconfigured.", err_msg),
                });
            } else if err_msg.contains("timeout") {
                findings.push(Finding {
                    check: "TLS Connection".to_string(),
                    status: "FAIL".to_string(),
                    detail: "Connection timed out. Server may be unreachable or firewall is blocking port 443".to_string(),
                });
            } else {
                findings.push(Finding {
                    check: "TLS Connection".to_string(),
                    status: "FAIL".to_string(),
                    detail: format!("Failed to connect: {}", err_msg),
                });
            }

            score -= 10;
            findings.push(Finding {
                check: "HSTS".to_string(),
                status: "SKIP".to_string(),
                detail: "Could not check headers—connection failed".to_string(),
            });
        }
    }

    // TLS version note
    findings.push(Finding {
        check: "TLS Version".to_string(),
        status: "INFO".to_string(),
        detail: "Use specialized tools (testssl.sh, SSL Labs) to verify TLS 1.2+ and cipher strength".to_string(),
    });

    // Certificate expiry note
    findings.push(Finding {
        check: "Certificate Expiry".to_string(),
        status: "INFO".to_string(),
        detail: "Use 'openssl s_client -connect HOST:443 -servername HOST' to check expiry date".to_string(),
    });

    Ok(SslAuditReport {
        host,
        port,
        score: score.max(0),
        findings,
    })
}
